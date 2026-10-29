package billing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/payforge"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/billingdispute"
	"github.com/plexusone/systemforge/identity/ent/billingorder"
	"github.com/plexusone/systemforge/identity/ent/billingrefund"
	"github.com/plexusone/systemforge/identity/ent/license"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/subscription"
	"github.com/plexusone/systemforge/marketplace"
)

// PlanSyncer writes an organization's platform subscription to the
// authorization graph. marketplace.SpiceDBSyncer implements it.
type PlanSyncer interface {
	SyncSubscription(ctx context.Context, sub *marketplace.Subscription) error
}

// PlanChange is what OnEntitlement receives: the entitlement payforge
// applied and the platform subscription it was stored as.
type PlanChange struct {
	OrganizationID uuid.UUID
	Entitlement    payforge.Entitlement
	Subscription   *marketplace.Subscription
}

// Sink is payforge's EntitlementSink, SaleSink, SellerSink and DisputeSink
// on the SystemForge Ent client, and the CheckoutCompleter of the webhook.
//
//   - A plan entitlement becomes the organization's platform subscription
//     (the subscription with no listing): its plan_tier is the plan the
//     organization is on, which is the spec's default plan when nothing
//     grants.
//   - A paid one-time checkout for a listing grants the buying organization
//     a license, matched through the order recorded at checkout.
//   - A full refund, an open dispute or a lost one suspends that license
//     (its valid_until is set); a dispute that is won restores it. A refund
//     is permanent, and a closed dispute stays closed.
//   - A seller's connected account records whether it can take charges,
//     which SellerGate turns into whether its paid listings can be
//     published.
//
// Every apply is idempotent and writes the authorization graph again from
// the stored state, whether or not the database changed, so a sync that
// failed is repaired when the provider redelivers the event. Database
// changes for one apply happen in one transaction; the graph is written
// after it commits, and a failure is returned so the event is retried.
type Sink struct {
	db            *ent.Client
	authz         marketplace.AuthzSyncer
	plans         PlanSyncer
	onEntitlement func(ctx context.Context, c PlanChange) error
	onSeller      func(ctx context.Context, s Seller) error
	log           *slog.Logger
	now           func() time.Time
}

var (
	_ payforge.EntitlementSink = (*Sink)(nil)
	_ payforge.SaleSink        = (*Sink)(nil)
	_ payforge.SellerSink      = (*Sink)(nil)
	_ payforge.DisputeSink     = (*Sink)(nil)
	_ CheckoutCompleter        = (*Sink)(nil)
)

// SinkOption configures a Sink.
type SinkOption func(*Sink)

// WithAuthzSyncer writes licenses to the authorization graph, for example
// marketplace.NewSpiceDBSyncer(client).
func WithAuthzSyncer(a marketplace.AuthzSyncer) SinkOption { return func(s *Sink) { s.authz = a } }

// WithPlanSyncer writes the platform subscription to the authorization
// graph on every entitlement.
func WithPlanSyncer(p PlanSyncer) SinkOption { return func(s *Sink) { s.plans = p } }

// OnEntitlement calls fn after every entitlement is stored, for the host's
// own state that follows the plan, such as limits or feature flags. An
// error is returned to payforge, and the event is retried; fn must be
// idempotent.
func OnEntitlement(fn func(ctx context.Context, c PlanChange) error) SinkOption {
	return func(s *Sink) { s.onEntitlement = fn }
}

// OnSeller calls fn after every change to a seller's account is stored,
// with the same retry rules as OnEntitlement.
func OnSeller(fn func(ctx context.Context, s Seller) error) SinkOption {
	return func(s *Sink) { s.onSeller = fn }
}

// WithSinkLogger sets where events the sink cannot act on are logged. It
// defaults to slog.Default().
func WithSinkLogger(l *slog.Logger) SinkOption { return func(s *Sink) { s.log = l } }

// NewSink returns a Sink. It panics on a nil client, a programming error.
func NewSink(db *ent.Client, opts ...SinkOption) *Sink {
	if db == nil {
		panic("billing: NewSink needs an Ent client")
	}
	s := &Sink{db: db, log: slog.Default(), now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Apply implements payforge.EntitlementSink.
func (s *Sink) Apply(ctx context.Context, e payforge.Entitlement) error {
	org, ok, err := s.organization(ctx, e.Subject)
	if err != nil || !ok {
		return err
	}
	err = withTx(ctx, s.db, func(tx *ent.Tx) error {
		c := tx.Client()
		row, err := c.Subscription.Query().
			Where(subscription.OrganizationIDEQ(org), subscription.ListingIDIsNil()).
			Only(ctx)
		if err != nil && !ent.IsNotFound(err) {
			return fmt.Errorf("billing: find platform subscription: %w", err)
		}
		end := e.ValidUntil
		if end.IsZero() {
			end = s.now()
			if row != nil {
				end = row.CurrentPeriodEnd
			}
		}
		status := subscriptionStatus(e)
		if row != nil {
			u := row.Update().SetPlanTier(e.Plan).SetStatus(status).SetCurrentPeriodEnd(end)
			if e.SubscriptionID != "" {
				u.SetStripeSubscriptionID(e.SubscriptionID)
			} else {
				u.ClearStripeSubscriptionID()
			}
			if e.CustomerID != "" {
				u.SetStripeCustomerID(e.CustomerID)
			}
			if err := u.Exec(ctx); err != nil {
				return fmt.Errorf("billing: update platform subscription: %w", err)
			}
		} else {
			cr := c.Subscription.Create().SetOrganizationID(org).SetPlanTier(e.Plan).
				SetStatus(status).SetCurrentPeriodEnd(end)
			if e.SubscriptionID != "" {
				cr.SetStripeSubscriptionID(e.SubscriptionID)
			}
			if e.CustomerID != "" {
				cr.SetStripeCustomerID(e.CustomerID)
			}
			if err := cr.Exec(ctx); err != nil {
				return fmt.Errorf("billing: create platform subscription: %w", err)
			}
		}
		if e.CustomerID == "" {
			return nil
		}
		err = linkCustomer(ctx, c, e.CustomerID, org)
		if errors.Is(err, ErrCustomerConflict) {
			s.log.WarnContext(ctx, "billing: customer is linked to another organization; not moved",
				"organization_id", org, "customer", e.CustomerID, "event", e.EventID)
			return nil
		}
		return err
	})
	if err != nil {
		return err
	}
	if s.plans == nil && s.onEntitlement == nil {
		return nil
	}
	sub, err := marketplace.NewEntSubscriptionService(s.db).GetByOrg(ctx, org)
	if err != nil {
		return fmt.Errorf("billing: read platform subscription: %w", err)
	}
	if s.plans != nil {
		if err := s.plans.SyncSubscription(ctx, sub); err != nil {
			return fmt.Errorf("billing: sync platform subscription: %w", err)
		}
	}
	if s.onEntitlement != nil {
		if err := s.onEntitlement(ctx, PlanChange{OrganizationID: org, Entitlement: e, Subscription: sub}); err != nil {
			return fmt.Errorf("billing: entitlement hook: %w", err)
		}
	}
	return nil
}

// subscriptionStatus maps an entitlement to a stored status. Without a
// subscription the organization is simply on the default plan, which is
// active; a provider status the schema does not have, which never grants,
// is stored as canceled.
func subscriptionStatus(e payforge.Entitlement) subscription.Status {
	if e.Status == "" {
		return subscription.StatusActive
	}
	st := subscription.Status(e.Status)
	if subscription.StatusValidator(st) == nil {
		return st
	}
	return subscription.StatusCanceled
}

// organization parses a subject and checks that the organization exists. A
// subject that is not one, which only metadata written outside SystemForge
// can produce, is logged and reported as not ok so the event is
// acknowledged instead of retried forever.
func (s *Sink) organization(ctx context.Context, subject string) (uuid.UUID, bool, error) {
	org, err := uuid.Parse(subject)
	if err != nil {
		s.log.WarnContext(ctx, "billing: subject is not an organization ID; ignored", "subject", subject)
		return uuid.Nil, false, nil
	}
	ok, err := s.db.Organization.Query().Where(organization.IDEQ(org)).Exist(ctx)
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("billing: find organization: %w", err)
	}
	if !ok {
		s.log.WarnContext(ctx, "billing: no such organization; ignored", "organization_id", org)
	}
	return org, ok, nil
}

// CompleteCheckout implements CheckoutCompleter. A checkout with no
// recorded order is not one SystemForge made and is ignored.
func (s *Sink) CompleteCheckout(ctx context.Context, ev payforge.Event) error {
	if ev.Checkout == nil {
		return nil
	}
	var touched []pair
	err := withTx(ctx, s.db, func(tx *ent.Tx) error {
		c := tx.Client()
		o, err := c.BillingOrder.Query().Where(billingorder.SessionIDEQ(ev.Checkout.SessionID)).Only(ctx)
		if ent.IsNotFound(err) {
			s.log.InfoContext(ctx, "billing: checkout has no recorded order; ignored",
				"session", ev.Checkout.SessionID, "event", ev.ID)
			return nil
		}
		if err != nil {
			return fmt.Errorf("billing: find order: %w", err)
		}
		if ev.Kind == payforge.EventCheckoutFailed || !ev.Checkout.Paid {
			// The delayed payment failed; the order was never granted.
			touched = append(touched, pair{o.ListingID, o.OrganizationID})
			return nil
		}
		if o.Status == billingorder.StatusPending {
			u := o.Update().SetStatus(billingorder.StatusPaid)
			if ev.Checkout.PaymentIntent != "" {
				u.SetPaymentIntent(ev.Checkout.PaymentIntent)
			}
			if o, err = u.Save(ctx); err != nil {
				return fmt.Errorf("billing: mark order paid: %w", err)
			}
		}
		p, err := s.settle(ctx, c, o)
		touched = append(touched, p)
		return err
	})
	if err != nil {
		return err
	}
	return s.syncLicenses(ctx, touched)
}

// ApplyRefund implements payforge.SaleSink. It keeps the highest refunded
// total seen for the charge, and a full refund suspends the license its
// order granted for good.
func (s *Sink) ApplyRefund(ctx context.Context, r payforge.SaleRefund) error {
	if r.ChargeID == "" {
		s.log.WarnContext(ctx, "billing: refund names no charge; ignored", "event", r.EventID)
		return nil
	}
	var touched []pair
	err := withTx(ctx, s.db, func(tx *ent.Tx) error {
		c := tx.Client()
		row, err := c.BillingRefund.Query().Where(billingrefund.ChargeIDEQ(r.ChargeID)).Only(ctx)
		switch {
		case ent.IsNotFound(err):
			err = c.BillingRefund.Create().SetChargeID(r.ChargeID).SetPaymentIntent(r.PaymentIntent).
				SetRefundedCents(r.RefundedCents).SetFull(r.Full).Exec(ctx)
		case err == nil:
			u := row.Update().SetRefundedCents(max(row.RefundedCents, r.RefundedCents)).SetFull(row.Full || r.Full)
			if row.PaymentIntent == "" && r.PaymentIntent != "" {
				u.SetPaymentIntent(r.PaymentIntent)
			}
			err = u.Exec(ctx)
		}
		if err != nil {
			return fmt.Errorf("billing: record refund: %w", err)
		}
		touched, err = s.settlePayment(ctx, c, r.PaymentIntent)
		return err
	})
	if err != nil {
		return err
	}
	if len(touched) == 0 {
		s.log.InfoContext(ctx, "billing: refund matches no recorded order", "charge", r.ChargeID, "event", r.EventID)
	}
	return s.syncLicenses(ctx, touched)
}

// ApplyDispute implements payforge.DisputeSink. An open or lost dispute
// suspends the license the disputed payment's order granted; a dispute that
// is won restores it.
func (s *Sink) ApplyDispute(ctx context.Context, d payforge.ChargeDispute) error {
	if d.DisputeID == "" {
		return nil
	}
	var touched []pair
	err := withTx(ctx, s.db, func(tx *ent.Tx) error {
		c := tx.Client()
		row, err := c.BillingDispute.Query().Where(billingdispute.DisputeIDEQ(d.DisputeID)).Only(ctx)
		switch {
		case ent.IsNotFound(err):
			err = c.BillingDispute.Create().SetDisputeID(d.DisputeID).SetChargeID(d.ChargeID).
				SetPaymentIntent(d.PaymentIntent).SetClosed(d.Closed).SetLost(d.Lost).Exec(ctx)
		case err == nil:
			u := row.Update().SetClosed(row.Closed || d.Closed).SetLost(row.Lost || d.Lost)
			if row.PaymentIntent == "" && d.PaymentIntent != "" {
				u.SetPaymentIntent(d.PaymentIntent)
			}
			err = u.Exec(ctx)
		}
		if err != nil {
			return fmt.Errorf("billing: record dispute: %w", err)
		}
		touched, err = s.settlePayment(ctx, c, d.PaymentIntent)
		return err
	})
	if err != nil {
		return err
	}
	return s.syncLicenses(ctx, touched)
}

// ApplySeller implements payforge.SellerSink.
func (s *Sink) ApplySeller(ctx context.Context, a payforge.SellerAccount) error {
	if _, ok, err := s.organization(ctx, a.Subject); err != nil || !ok {
		return err
	}
	var org uuid.UUID
	err := withTx(ctx, s.db, func(tx *ent.Tx) error {
		var err error
		org, err = upsertSeller(ctx, tx.Client(), a, true)
		return err
	})
	if errors.Is(err, errSellerConflict) {
		s.log.WarnContext(ctx, "billing: connected account is recorded for another organization; ignored",
			"account", a.AccountID, "event", a.EventID)
		return nil
	}
	if err != nil || s.onSeller == nil {
		return err
	}
	return s.onSeller(ctx, Seller{
		OrganizationID: org, AccountID: a.AccountID, ChargesEnabled: a.ChargesEnabled,
		PayoutsEnabled: a.PayoutsEnabled, DetailsSubmitted: a.DetailsSubmitted,
	})
}

// pair is a listing and an organization whose license may have changed.
type pair struct{ listing, org uuid.UUID }

// settlePayment settles every order paid by a payment.
func (s *Sink) settlePayment(ctx context.Context, c *ent.Client, paymentIntent string) ([]pair, error) {
	if paymentIntent == "" {
		return nil, nil
	}
	orders, err := c.BillingOrder.Query().Where(billingorder.PaymentIntentEQ(paymentIntent)).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("billing: find orders: %w", err)
	}
	var out []pair
	for _, o := range orders {
		p, err := s.settle(ctx, c, o)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// settle brings the license of a paid order in line with what has happened
// to its payment. A payment refunded in full, or under an open or lost
// dispute, holds no license: the order's license is suspended. Otherwise
// the order holds one: it is granted if the organization has none for the
// listing, and restored if it was suspended. The license is never deleted,
// so seat assignments survive a dispute that is won.
func (s *Sink) settle(ctx context.Context, c *ent.Client, o *ent.BillingOrder) (pair, error) {
	p := pair{o.ListingID, o.OrganizationID}
	if o.Status == billingorder.StatusPending {
		return p, nil
	}
	refunded, blocked, err := paymentBlocked(ctx, c, o.PaymentIntent)
	if err != nil {
		return p, err
	}
	if refunded && o.Status != billingorder.StatusRefunded {
		if err := o.Update().SetStatus(billingorder.StatusRefunded).Exec(ctx); err != nil {
			return p, fmt.Errorf("billing: mark order refunded: %w", err)
		}
	}
	now := s.now()
	if blocked {
		if o.LicenseID == nil {
			return p, nil
		}
		_, err := c.License.Update().
			Where(license.IDEQ(*o.LicenseID), license.Or(license.ValidUntilIsNil(), license.ValidUntilGT(now))).
			SetValidUntil(now).
			Save(ctx)
		if err != nil {
			return p, fmt.Errorf("billing: suspend license: %w", err)
		}
		return p, nil
	}
	if o.LicenseID != nil {
		if _, err := c.License.Update().Where(license.IDEQ(*o.LicenseID)).ClearValidUntil().Save(ctx); err != nil {
			return p, fmt.Errorf("billing: restore license: %w", err)
		}
		return p, nil
	}
	held, err := c.License.Query().Where(license.ListingIDEQ(o.ListingID), license.OrganizationIDEQ(o.OrganizationID)).Only(ctx)
	switch {
	case err == nil && (held.ValidUntil == nil || held.ValidUntil.After(now)):
		s.log.WarnContext(ctx, "billing: organization already holds a license for the listing; paid order grants none",
			"order", o.SessionID, "listing_id", o.ListingID, "organization_id", o.OrganizationID)
		return p, nil
	case err == nil:
		// A license an earlier order lost, bought again: this order takes it
		// over, so a late event for the earlier order cannot suspend it.
		if err := c.BillingOrder.Update().Where(billingorder.LicenseIDEQ(held.ID)).ClearLicenseID().Exec(ctx); err != nil {
			return p, fmt.Errorf("billing: release license: %w", err)
		}
		if err := held.Update().ClearValidUntil().SetPurchasedBy(o.PurchaserID).Exec(ctx); err != nil {
			return p, fmt.Errorf("billing: restore license: %w", err)
		}
		if err := o.Update().SetLicenseID(held.ID).Exec(ctx); err != nil {
			return p, fmt.Errorf("billing: record license: %w", err)
		}
		return p, nil
	case !ent.IsNotFound(err):
		return p, fmt.Errorf("billing: find license: %w", err)
	}
	l, err := c.License.Create().SetListingID(o.ListingID).SetOrganizationID(o.OrganizationID).
		SetPurchasedBy(o.PurchaserID).SetLicenseType(license.LicenseTypeUnlimited).SetValidFrom(now).Save(ctx)
	if err != nil {
		return p, fmt.Errorf("billing: grant license: %w", err)
	}
	if err := o.Update().SetLicenseID(l.ID).Exec(ctx); err != nil {
		return p, fmt.Errorf("billing: record license: %w", err)
	}
	return p, nil
}

// paymentBlocked reports whether a payment was refunded in full, and
// whether it holds no license: refunded, or under an open or lost dispute.
func paymentBlocked(ctx context.Context, c *ent.Client, paymentIntent *string) (refunded, blocked bool, err error) {
	if paymentIntent == nil || *paymentIntent == "" {
		return false, false, nil
	}
	refunded, err = c.BillingRefund.Query().
		Where(billingrefund.PaymentIntentEQ(*paymentIntent), billingrefund.Full(true)).Exist(ctx)
	if err != nil {
		return false, false, fmt.Errorf("billing: find refunds: %w", err)
	}
	disputed, err := c.BillingDispute.Query().
		Where(billingdispute.PaymentIntentEQ(*paymentIntent),
			billingdispute.Or(billingdispute.Closed(false), billingdispute.Lost(true))).
		Exist(ctx)
	if err != nil {
		return false, false, fmt.Errorf("billing: find disputes: %w", err)
	}
	return refunded, refunded || disputed, nil
}

// syncLicenses writes each listing and organization's license to the
// authorization graph as it is stored now: granted while a valid license
// exists, revoked otherwise. It runs on every apply, whether or not the
// database changed.
func (s *Sink) syncLicenses(ctx context.Context, pairs []pair) error {
	if s.authz == nil {
		return nil
	}
	licenses := marketplace.NewEntLicenseService(s.db, nil)
	done := map[pair]bool{}
	for _, p := range pairs {
		if done[p] {
			continue
		}
		done[p] = true
		l, err := licenses.GetByListingAndOrg(ctx, p.listing, p.org)
		switch {
		case err == nil && l.IsValid():
			err = s.authz.SyncLicense(ctx, l)
		case err == nil || errors.Is(err, marketplace.ErrLicenseNotFound):
			err = s.authz.SyncLicenseRevocation(ctx, &marketplace.License{ListingID: p.listing, OrganizationID: p.org})
		}
		if err != nil {
			return fmt.Errorf("billing: sync license: %w", err)
		}
	}
	return nil
}
