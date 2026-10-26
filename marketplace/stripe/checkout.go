// Package stripe provides Stripe integration for the marketplace.
package stripe

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/stripe/stripe-go/v84"
	"github.com/stripe/stripe-go/v84/checkout/session"

	"github.com/plexusone/systemforge/marketplace"
)

// Config holds Stripe configuration.
type Config struct {
	// SecretKey is the Stripe secret API key.
	SecretKey string

	// WebhookSecret is the Stripe webhook signing secret. ProcessWebhook
	// refuses every event with ErrWebhookSecretRequired while it is empty.
	WebhookSecret string

	// ConnectAccountID is the Stripe Connect account ID (optional, for platforms).
	ConnectAccountID string
}

// CheckoutService implements marketplace.CheckoutService using Stripe.
type CheckoutService struct {
	config    Config
	listings  marketplace.ListingService
	licenses  marketplace.LicenseService
	authzSync marketplace.AuthzSyncer
	purchaser marketplace.PurchaserChecker
}

// CheckoutOption configures a CheckoutService.
type CheckoutOption func(*CheckoutService)

// WithPurchaserChecker refuses checkout to managed principals with
// marketplace.ErrManagedPurchaser. Deployments that enable managed
// principals must set it.
func WithPurchaserChecker(c marketplace.PurchaserChecker) CheckoutOption {
	return func(s *CheckoutService) { s.purchaser = c }
}

// NewCheckoutService creates a new Stripe checkout service.
func NewCheckoutService(cfg Config, listings marketplace.ListingService, licenses marketplace.LicenseService, authzSync marketplace.AuthzSyncer, opts ...CheckoutOption) *CheckoutService {
	stripe.Key = cfg.SecretKey
	s := &CheckoutService{
		config:    cfg,
		listings:  listings,
		licenses:  licenses,
		authzSync: authzSync,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// CreateCheckoutSession creates a Stripe checkout session for a listing.
func (s *CheckoutService) CreateCheckoutSession(ctx context.Context, req marketplace.CheckoutRequest) (*marketplace.CheckoutSession, error) {
	if s.purchaser != nil {
		managed, err := s.purchaser.IsManaged(ctx, req.PurchaserID)
		if err != nil {
			return nil, fmt.Errorf("failed to check purchaser: %w", err)
		}
		if managed {
			return nil, marketplace.ErrManagedPurchaser
		}
	}

	// Get the listing
	listing, err := s.listings.Get(ctx, req.ListingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get listing: %w", err)
	}

	if !listing.IsPublished() {
		return nil, fmt.Errorf("listing is not published")
	}

	// Build line items
	lineItems, err := s.buildLineItems(listing, req.Seats)
	if err != nil {
		return nil, err
	}

	// Determine mode based on pricing model
	mode := stripe.CheckoutSessionModePayment
	if listing.PricingModel == marketplace.PricingSubscription {
		mode = stripe.CheckoutSessionModeSubscription
	}

	// Create checkout session params
	params := &stripe.CheckoutSessionParams{
		Mode:       stripe.String(string(mode)),
		LineItems:  lineItems,
		SuccessURL: stripe.String(req.SuccessURL + "?session_id={CHECKOUT_SESSION_ID}"),
		CancelURL:  stripe.String(req.CancelURL),
		Metadata: map[string]string{
			"listing_id":      req.ListingID.String(),
			"organization_id": req.OrganizationID.String(),
			"purchaser_id":    req.PurchaserID.String(),
		},
		ClientReferenceID: stripe.String(fmt.Sprintf("%s:%s", req.OrganizationID.String(), req.ListingID.String())),
	}

	if req.Seats != nil {
		params.Metadata["seats"] = fmt.Sprintf("%d", *req.Seats)
	}

	// Create the session
	sess, err := session.New(params)
	if err != nil {
		return nil, fmt.Errorf("failed to create checkout session: %w", err)
	}

	return &marketplace.CheckoutSession{
		SessionID: sess.ID,
		URL:       sess.URL,
	}, nil
}

// buildLineItems builds Stripe line items from a listing.
func (s *CheckoutService) buildLineItems(listing *marketplace.Listing, seats *int) ([]*stripe.CheckoutSessionLineItemParams, error) {
	quantity := int64(1)
	if seats != nil && *seats > 0 {
		quantity = int64(*seats)
	}

	// For free listings, we don't need Stripe
	if listing.IsFree() {
		return nil, fmt.Errorf("cannot create checkout for free listing")
	}

	var priceData *stripe.CheckoutSessionLineItemPriceDataParams

	switch listing.PricingModel {
	case marketplace.PricingOneTime:
		priceData = &stripe.CheckoutSessionLineItemPriceDataParams{
			Currency:   stripe.String(listing.Currency),
			UnitAmount: stripe.Int64(listing.PriceCents),
			ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
				Name:        stripe.String(listing.Title),
				Description: stripe.String(listing.Description),
			},
		}

	case marketplace.PricingSubscription:
		priceData = &stripe.CheckoutSessionLineItemPriceDataParams{
			Currency:   stripe.String(listing.Currency),
			UnitAmount: stripe.Int64(listing.PriceCents),
			Recurring: &stripe.CheckoutSessionLineItemPriceDataRecurringParams{
				Interval: stripe.String(string(stripe.PriceRecurringIntervalMonth)),
			},
			ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
				Name:        stripe.String(listing.Title),
				Description: stripe.String(listing.Description),
			},
		}

	case marketplace.PricingPerSeat:
		priceData = &stripe.CheckoutSessionLineItemPriceDataParams{
			Currency:   stripe.String(listing.Currency),
			UnitAmount: stripe.Int64(listing.PriceCents),
			Recurring: &stripe.CheckoutSessionLineItemPriceDataRecurringParams{
				Interval: stripe.String(string(stripe.PriceRecurringIntervalMonth)),
			},
			ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
				Name:        stripe.String(listing.Title + " (per seat)"),
				Description: stripe.String(listing.Description),
			},
		}

	default:
		return nil, fmt.Errorf("unsupported pricing model: %s", listing.PricingModel)
	}

	return []*stripe.CheckoutSessionLineItemParams{
		{
			PriceData: priceData,
			Quantity:  stripe.Int64(quantity),
		},
	}, nil
}

// ProcessWebhook handles Stripe webhook events. It refuses every event
// with ErrWebhookSecretRequired when Config.WebhookSecret is empty.
func (s *CheckoutService) ProcessWebhook(ctx context.Context, payload []byte, signature string) error {
	if s.config.WebhookSecret == "" {
		return ErrWebhookSecretRequired
	}
	event, err := VerifyWebhook(payload, signature, s.config.WebhookSecret)
	if err != nil {
		return fmt.Errorf("invalid webhook signature: %w", err)
	}

	switch event.Type {
	case "checkout.session.completed", "checkout.session.async_payment_succeeded":
		return s.handleCheckoutCompleted(ctx, event)
	case "customer.subscription.created":
		return s.handleSubscriptionCreated(ctx, event)
	case "customer.subscription.updated":
		return s.handleSubscriptionUpdated(ctx, event)
	case "customer.subscription.deleted":
		return s.handleSubscriptionDeleted(ctx, event)
	case "invoice.paid":
		return s.handleInvoicePaid(ctx, event)
	case "invoice.payment_failed":
		return s.handleInvoicePaymentFailed(ctx, event)
	default:
		// Ignore unhandled event types
		return nil
	}
}

// handleCheckoutCompleted grants a license once a checkout is paid. A
// checkout completed with a delayed payment method is still unpaid; its
// license is granted on checkout.session.async_payment_succeeded.
func (s *CheckoutService) handleCheckoutCompleted(ctx context.Context, event *stripe.Event) error {
	sess, err := parseCheckoutSession(event)
	if err != nil {
		return err
	}
	switch sess.PaymentStatus {
	case stripe.CheckoutSessionPaymentStatusPaid, stripe.CheckoutSessionPaymentStatusNoPaymentRequired:
	default:
		return nil
	}

	// Extract metadata
	listingID, err := uuid.Parse(sess.Metadata["listing_id"])
	if err != nil {
		return fmt.Errorf("invalid listing_id in metadata: %w", err)
	}
	orgID, err := uuid.Parse(sess.Metadata["organization_id"])
	if err != nil {
		return fmt.Errorf("invalid organization_id in metadata: %w", err)
	}
	purchaserID, err := uuid.Parse(sess.Metadata["purchaser_id"])
	if err != nil {
		return fmt.Errorf("invalid purchaser_id in metadata: %w", err)
	}

	// Get listing to determine license type
	listing, err := s.listings.Get(ctx, listingID)
	if err != nil {
		return fmt.Errorf("failed to get listing: %w", err)
	}

	// Determine license type and seats
	licenseType := marketplace.LicenseUnlimited
	var seats *int
	if listing.PricingModel == marketplace.PricingPerSeat {
		licenseType = marketplace.LicenseSeatBased
		// A seat-based license without a seat count would be unlimited.
		n, err := strconv.Atoi(sess.Metadata["seats"])
		if err != nil || n < 1 {
			return fmt.Errorf("invalid seats in metadata: %q", sess.Metadata["seats"])
		}
		seats = &n
	}

	// Create the license
	license := &marketplace.License{
		ID:             uuid.New(),
		ListingID:      listingID,
		OrganizationID: orgID,
		LicenseType:    licenseType,
		Seats:          seats,
		ValidFrom:      time.Now(),
		PurchasedBy:    purchaserID,
	}

	// For subscriptions, set the Stripe subscription ID
	if sess.Subscription != nil {
		subID := sess.Subscription.ID
		license.StripeSubscriptionID = &subID
	}

	if err := s.licenses.Grant(ctx, license); err != nil {
		// Check if already licensed (idempotency)
		if errors.Is(err, marketplace.ErrAlreadyLicensed) {
			return nil
		}
		return fmt.Errorf("failed to grant license: %w", err)
	}

	return nil
}

// handleSubscriptionCreated handles new subscription creation.
func (s *CheckoutService) handleSubscriptionCreated(ctx context.Context, event *stripe.Event) error {
	// Subscription creation is typically handled by checkout.session.completed
	// This handler can be used for subscriptions created outside of checkout
	return nil
}

// handleSubscriptionUpdated reconciles the license a subscription pays for
// with the subscription's status and quantity:
//
//   - active or trialing: the license is valid; a license suspended
//     earlier is restored, and a seat-based license takes the
//     subscription's quantity as its seat count.
//   - past_due: unchanged while Stripe retries the payment; Stripe moves
//     the subscription to unpaid or canceled when its retries end.
//   - unpaid, paused, incomplete_expired or canceled: the license is
//     suspended (ValidUntil is set to now) and its access is removed from
//     the authorization system, so that a later payment can restore it.
//   - incomplete: unchanged; checkout grants no license before payment.
//
// A subscription with no license is ignored.
func (s *CheckoutService) handleSubscriptionUpdated(ctx context.Context, event *stripe.Event) error {
	sub, err := parseSubscription(event)
	if err != nil {
		return err
	}
	lic, err := s.licenses.GetByStripeSubscriptionID(ctx, sub.ID)
	if errors.Is(err, marketplace.ErrLicenseNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	switch sub.Status {
	case stripe.SubscriptionStatusActive, stripe.SubscriptionStatusTrialing:
		return s.activateLicense(ctx, lic, sub)
	case stripe.SubscriptionStatusUnpaid, stripe.SubscriptionStatusPaused,
		stripe.SubscriptionStatusIncompleteExpired, stripe.SubscriptionStatusCanceled:
		return s.suspendLicense(ctx, lic)
	default:
		return nil
	}
}

// activateLicense restores a suspended license and applies the
// subscription's quantity to a seat-based license.
func (s *CheckoutService) activateLicense(ctx context.Context, lic *marketplace.License, sub *stripe.Subscription) error {
	suspended := lic.ValidUntil != nil
	changed := suspended
	lic.ValidUntil = nil
	if lic.LicenseType == marketplace.LicenseSeatBased {
		if q := subscriptionQuantity(sub); q > 0 && (lic.Seats == nil || *lic.Seats != q) {
			lic.Seats = &q
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := s.licenses.Update(ctx, lic); err != nil {
		return fmt.Errorf("failed to update license for subscription %s: %w", sub.ID, err)
	}
	if suspended && s.authzSync != nil {
		if err := s.authzSync.SyncLicense(ctx, lic); err != nil {
			return fmt.Errorf("failed to sync restored license to authz: %w", err)
		}
	}
	return nil
}

// suspendLicense ends a license's validity now and removes its access from
// the authorization system. A license already suspended is left as it is,
// so redelivered events are harmless.
func (s *CheckoutService) suspendLicense(ctx context.Context, lic *marketplace.License) error {
	now := time.Now()
	if lic.ValidUntil != nil && !lic.ValidUntil.After(now) {
		return nil
	}
	lic.ValidUntil = &now
	if err := s.licenses.Update(ctx, lic); err != nil {
		return fmt.Errorf("failed to suspend license %s: %w", lic.ID, err)
	}
	if s.authzSync != nil {
		if err := s.authzSync.SyncLicenseRevocation(ctx, lic); err != nil {
			return fmt.Errorf("failed to sync suspended license to authz: %w", err)
		}
	}
	return nil
}

// subscriptionQuantity returns the total quantity of a subscription's
// items, or 0 when it has none.
func subscriptionQuantity(sub *stripe.Subscription) int {
	if sub.Items == nil {
		return 0
	}
	var total int64
	for _, item := range sub.Items.Data {
		if item != nil {
			total += item.Quantity
		}
	}
	return int(total)
}

// handleSubscriptionDeleted revokes the license an ended subscription paid
// for. A subscription with no license, such as one already revoked, is
// ignored, so redelivered events are harmless.
func (s *CheckoutService) handleSubscriptionDeleted(ctx context.Context, event *stripe.Event) error {
	sub, err := parseSubscription(event)
	if err != nil {
		return err
	}
	lic, err := s.licenses.GetByStripeSubscriptionID(ctx, sub.ID)
	if errors.Is(err, marketplace.ErrLicenseNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.licenses.Revoke(ctx, lic.ID); err != nil && !errors.Is(err, marketplace.ErrLicenseNotFound) {
		return fmt.Errorf("failed to revoke license for subscription %s: %w", sub.ID, err)
	}
	return nil
}

// handleInvoicePaid handles successful invoice payment.
// It changes nothing: a subscription whose payment recovers is reported by
// customer.subscription.updated with status active, which restores a
// suspended license.
func (s *CheckoutService) handleInvoicePaid(ctx context.Context, event *stripe.Event) error {
	return nil
}

// handleInvoicePaymentFailed handles failed invoice payment.
// It changes nothing: Stripe reports the subscription's resulting status
// (past_due while retrying, then unpaid or canceled) through
// customer.subscription.updated and customer.subscription.deleted, which
// suspend or revoke the license.
func (s *CheckoutService) handleInvoicePaymentFailed(ctx context.Context, event *stripe.Event) error {
	return nil
}

// Ensure CheckoutService implements marketplace.CheckoutService.
var _ marketplace.CheckoutService = (*CheckoutService)(nil)
