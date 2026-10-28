package billing

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/payforge"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/marketplace"
)

// fakeAuthz records the graph writes and fails the next fail calls.
type fakeAuthz struct {
	mu      sync.Mutex
	fail    int
	granted map[pair]bool
	writes  int
	plans   int
}

func newFakeAuthz() *fakeAuthz { return &fakeAuthz{granted: map[pair]bool{}} }

func (f *fakeAuthz) failing() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.fail > 0 {
		f.fail--
		return errors.New("authorization graph unavailable")
	}
	return nil
}

func (f *fakeAuthz) set(l *marketplace.License, v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.granted[pair{l.ListingID, l.OrganizationID}] = v
}

func (f *fakeAuthz) has(listing, org uuid.UUID) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.granted[pair{listing, org}]
}

func (f *fakeAuthz) SyncListing(context.Context, *marketplace.Listing) error { return nil }
func (f *fakeAuthz) SyncLicense(_ context.Context, l *marketplace.License) error {
	if err := f.failing(); err != nil {
		return err
	}
	f.set(l, true)
	return nil
}
func (f *fakeAuthz) SyncLicenseRevocation(_ context.Context, l *marketplace.License) error {
	if err := f.failing(); err != nil {
		return err
	}
	f.set(l, false)
	return nil
}
func (f *fakeAuthz) SyncSeatAssignment(context.Context, *marketplace.SeatAssignment) error {
	return nil
}
func (f *fakeAuthz) SyncSeatUnassignment(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (f *fakeAuthz) SyncSubscription(context.Context, *marketplace.Subscription) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plans++
	return nil
}

// fixture is a seller organization with a published one-time listing, and a
// buying organization with a purchaser.
type fixture struct {
	db        *ent.Client
	store     *Store
	sink      *Sink
	authz     *fakeAuthz
	seller    uuid.UUID
	buyer     uuid.UUID
	purchaser uuid.UUID
	listing   uuid.UUID
	changes   []PlanChange
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{db: openDB(t), authz: newFakeAuthz()}
	f.store = NewStore(f.db)
	f.sink = NewSink(f.db, WithAuthzSyncer(f.authz), WithPlanSyncer(f.authz),
		OnEntitlement(func(_ context.Context, c PlanChange) error {
			f.changes = append(f.changes, c)
			return nil
		}))
	org := func(slug string) uuid.UUID {
		o, err := f.db.Organization.Create().SetName(slug).SetSlug(slug + "-" + uuid.NewString()[:8]).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return o.ID
	}
	f.seller, f.buyer = org("seller"), org("buyer")
	p, err := f.db.Principal.Create().SetType("human").SetIdentifier("buyer@example.com").SetDisplayName("Buyer").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.purchaser = p.ID
	listings := marketplace.NewEntListingService(f.db, nil)
	l := &marketplace.Listing{
		ID: uuid.New(), CreatorOrgID: f.seller, OwnerID: p.ID, ProductType: "template",
		Title: "A template", PricingModel: marketplace.PricingOneTime, PriceCents: 2500, Currency: "usd",
	}
	if err := listings.Create(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err := listings.Publish(ctx, l.ID); err != nil {
		t.Fatal(err)
	}
	f.listing = l.ID
	return f
}

// order records checkout cs_1 for the listing, paid by pi_1, and returns
// the event of its completion.
func (f *fixture) order(t *testing.T) payforge.Event {
	t.Helper()
	return f.orderPaidBy(t, "cs_1", "pi_1")
}

func (f *fixture) orderPaidBy(t *testing.T, session, paymentIntent string) payforge.Event {
	t.Helper()
	err := f.store.RecordOrder(context.Background(), Order{
		SessionID: session, ListingID: f.listing, OrganizationID: f.buyer, PurchaserID: f.purchaser, AmountCents: 2500,
	})
	if err != nil {
		t.Fatal(err)
	}
	return payforge.Event{
		ID: "evt_" + session, Kind: payforge.EventCheckoutCompleted, Subject: f.buyer.String(),
		Checkout: &payforge.CheckoutResult{SessionID: session, Mode: "payment", Paid: true, PaymentIntent: paymentIntent},
	}
}

// licensed reports whether the buyer holds a valid license in the database.
func (f *fixture) licensed(t *testing.T) bool {
	t.Helper()
	ok, err := marketplace.NewEntLicenseService(f.db, nil).Check(context.Background(), f.listing, f.buyer)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func (f *fixture) expect(t *testing.T, want bool) {
	t.Helper()
	if got := f.licensed(t); got != want {
		t.Fatalf("license valid = %v, want %v", got, want)
	}
	if got := f.authz.has(f.listing, f.buyer); got != want {
		t.Fatalf("graph grants = %v, want %v", got, want)
	}
}

func TestSinkAppliesPlans(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	end := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	pro := payforge.Entitlement{
		Subject: f.buyer.String(), Plan: "pro", Granted: true, SubscribedPlan: "pro", Status: "active",
		ValidUntil: end, SubscriptionID: "sub_1", CustomerID: "cus_1", EventID: "evt_1",
	}
	for range 2 {
		if err := f.sink.Apply(ctx, pro); err != nil {
			t.Fatal(err)
		}
	}
	subs := marketplace.NewEntSubscriptionService(f.db)
	sub, err := subs.GetByOrg(ctx, f.buyer)
	if err != nil {
		t.Fatal(err)
	}
	if sub.PlanTier != "pro" || sub.Status != marketplace.SubscriptionStatusActive || sub.StripeSubscriptionID != "sub_1" || !sub.CurrentPeriodEnd.Equal(end) {
		t.Fatalf("platform subscription = %+v", sub)
	}
	if got, err := f.store.SubjectForCustomer(ctx, "cus_1"); err != nil || got != f.buyer.String() {
		t.Fatalf("customer not linked: %q, %v", got, err)
	}
	// Every apply syncs and calls the hook, even when nothing changed.
	if f.authz.plans != 2 || len(f.changes) != 2 || f.changes[1].Subscription.PlanTier != "pro" {
		t.Fatalf("plan syncs %d, hook calls %d", f.authz.plans, len(f.changes))
	}

	drop := payforge.Entitlement{Subject: f.buyer.String(), Plan: "free", SubscribedPlan: "pro", Status: "incomplete_expired", SubscriptionID: "sub_1", CustomerID: "cus_1"}
	if err := f.sink.Apply(ctx, drop); err != nil {
		t.Fatal(err)
	}
	sub, err = subs.GetByOrg(ctx, f.buyer)
	if err != nil {
		t.Fatal(err)
	}
	if sub.PlanTier != "free" || sub.Status != marketplace.SubscriptionStatusCanceled || !sub.CurrentPeriodEnd.Equal(end) {
		t.Fatalf("after the drop = %+v", sub)
	}
	if n, err := f.db.Subscription.Query().Count(ctx); err != nil || n != 1 {
		t.Fatalf("%d platform subscriptions, %v", n, err)
	}
}

func TestSinkIgnoresUnknownOrganizations(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	for _, subject := range []string{"not-a-uuid", uuid.NewString()} {
		if err := f.sink.Apply(ctx, payforge.Entitlement{Subject: subject, Plan: "pro", Granted: true}); err != nil {
			t.Fatalf("%s: %v", subject, err)
		}
		if err := f.sink.ApplySeller(ctx, payforge.SellerAccount{Subject: subject, AccountID: "acct_1"}); err != nil {
			t.Fatalf("%s: %v", subject, err)
		}
	}
	if n, err := f.db.Subscription.Query().Count(ctx); err != nil || n != 0 {
		t.Fatalf("%d subscriptions, %v", n, err)
	}
}

func TestSinkGrantsAPaidCheckoutOnce(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	ev := f.order(t)
	for range 2 {
		if err := f.sink.CompleteCheckout(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	f.expect(t, true)
	if n, err := f.db.License.Query().Count(ctx); err != nil || n != 1 {
		t.Fatalf("%d licenses, %v", n, err)
	}
	if f.authz.writes != 2 {
		t.Fatalf("%d graph writes, want one per apply", f.authz.writes)
	}
	// A checkout SystemForge did not record is not ours.
	foreign := ev
	foreign.Checkout = &payforge.CheckoutResult{SessionID: "cs_other", Mode: "payment", Paid: true}
	if err := f.sink.CompleteCheckout(ctx, foreign); err != nil {
		t.Fatal(err)
	}
}

func TestSinkRetriesAFailedSync(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	ev := f.order(t)

	f.authz.fail = 1
	if err := f.sink.CompleteCheckout(ctx, ev); err == nil {
		t.Fatal("a failed graph write was not reported")
	}
	if !f.licensed(t) || f.authz.has(f.listing, f.buyer) {
		t.Fatal("expected the license stored and the graph behind")
	}
	// The redelivery finds the license already granted and writes the graph.
	if err := f.sink.CompleteCheckout(ctx, ev); err != nil {
		t.Fatal(err)
	}
	f.expect(t, true)

	full := payforge.SaleRefund{Subject: f.buyer.String(), ChargeID: "ch_1", PaymentIntent: "pi_1", AmountCents: 2500, RefundedCents: 2500, Full: true}
	f.authz.fail = 1
	if err := f.sink.ApplyRefund(ctx, full); err == nil {
		t.Fatal("a failed revocation was not reported")
	}
	if f.licensed(t) || !f.authz.has(f.listing, f.buyer) {
		t.Fatal("expected the license suspended and the graph behind")
	}
	if err := f.sink.ApplyRefund(ctx, full); err != nil {
		t.Fatal(err)
	}
	f.expect(t, false)
}

func TestSinkRefunds(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	ev := f.order(t)
	if err := f.sink.CompleteCheckout(ctx, ev); err != nil {
		t.Fatal(err)
	}
	refund := func(cents int64, full bool) {
		t.Helper()
		err := f.sink.ApplyRefund(ctx, payforge.SaleRefund{
			Subject: f.buyer.String(), ChargeID: "ch_1", PaymentIntent: "pi_1", AmountCents: 2500, RefundedCents: cents, Full: full,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	refund(500, false)
	f.expect(t, true)
	refund(2500, true)
	f.expect(t, false)
	// A late event for the earlier partial refund does not reopen the sale.
	refund(500, false)
	f.expect(t, false)
	if err := f.sink.CompleteCheckout(ctx, ev); err != nil {
		t.Fatal(err)
	}
	f.expect(t, false)
}

func TestSinkBuyingAgainAfterARefund(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if err := f.sink.CompleteCheckout(ctx, f.order(t)); err != nil {
		t.Fatal(err)
	}
	full := payforge.SaleRefund{ChargeID: "ch_1", PaymentIntent: "pi_1", RefundedCents: 2500, Full: true}
	if err := f.sink.ApplyRefund(ctx, full); err != nil {
		t.Fatal(err)
	}
	f.expect(t, false)
	if err := f.sink.CompleteCheckout(ctx, f.orderPaidBy(t, "cs_2", "pi_2")); err != nil {
		t.Fatal(err)
	}
	f.expect(t, true)
	// A redelivered refund of the first purchase leaves the second alone.
	if err := f.sink.ApplyRefund(ctx, full); err != nil {
		t.Fatal(err)
	}
	f.expect(t, true)
	if n, err := f.db.License.Query().Count(ctx); err != nil || n != 1 {
		t.Fatalf("%d licenses, %v", n, err)
	}
}

func TestSinkRefundBeforeCheckout(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	ev := f.order(t)
	if err := f.sink.ApplyRefund(ctx, payforge.SaleRefund{ChargeID: "ch_1", PaymentIntent: "pi_1", RefundedCents: 2500, Full: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.sink.CompleteCheckout(ctx, ev); err != nil {
		t.Fatal(err)
	}
	f.expect(t, false)
}

func TestSinkDisputes(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if err := f.sink.CompleteCheckout(ctx, f.order(t)); err != nil {
		t.Fatal(err)
	}
	dispute := func(d payforge.ChargeDispute) {
		t.Helper()
		d.DisputeID, d.ChargeID, d.PaymentIntent = "dp_1", "ch_1", "pi_1"
		if err := f.sink.ApplyDispute(ctx, d); err != nil {
			t.Fatal(err)
		}
	}
	dispute(payforge.ChargeDispute{Status: "needs_response"})
	f.expect(t, false)
	dispute(payforge.ChargeDispute{Status: "won", Closed: true, Won: true})
	f.expect(t, true)
	// A late "opened" event does not reopen a closed dispute.
	dispute(payforge.ChargeDispute{Status: "needs_response"})
	f.expect(t, true)

	if err := f.sink.ApplyDispute(ctx, payforge.ChargeDispute{DisputeID: "dp_2", PaymentIntent: "pi_1", Closed: true, Lost: true}); err != nil {
		t.Fatal(err)
	}
	f.expect(t, false)
}

func TestSinkSellers(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	gate := NewSellerGate(f.store)
	can := func() bool {
		t.Helper()
		ok, err := gate.CanPublish(ctx, f.seller)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if can() {
		t.Fatal("a seller without an account can publish")
	}
	if err := f.store.LinkSeller(ctx, f.seller, "acct_1"); err != nil {
		t.Fatal(err)
	}
	if can() {
		t.Fatal("a seller that has not onboarded can publish")
	}
	apply := func(a payforge.SellerAccount) {
		t.Helper()
		if err := f.sink.ApplySeller(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	apply(payforge.SellerAccount{Subject: f.seller.String(), AccountID: "acct_1", ChargesEnabled: true, DetailsSubmitted: true})
	if !can() {
		t.Fatal("an enabled seller cannot publish")
	}
	// Another organization naming the same account changes nothing.
	apply(payforge.SellerAccount{Subject: f.buyer.String(), AccountID: "acct_1"})
	if !can() {
		t.Fatal("another organization's event changed the seller")
	}
	apply(payforge.SellerAccount{Subject: f.seller.String(), AccountID: "acct_1", ChargesEnabled: false})
	if can() {
		t.Fatal("a paused seller can publish")
	}

	// Publishing a paid listing follows the gate.
	listings := marketplace.NewEntListingService(f.db, nil).WithPublishGate(gate)
	if err := listings.Publish(ctx, f.listing); !errors.Is(err, marketplace.ErrSellerNotReady) {
		t.Fatalf("publish by a paused seller: %v", err)
	}
	apply(payforge.SellerAccount{Subject: f.seller.String(), AccountID: "acct_1", ChargesEnabled: true})
	if err := listings.Publish(ctx, f.listing); err != nil {
		t.Fatal(err)
	}
}
