package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stripe/stripe-go/v84"
	"github.com/stripe/stripe-go/v84/webhook"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/marketplace"
)

const testSecret = "whsec_test_secret" //nolint:gosec // G101: a test-only webhook signing secret

type webhookFixture struct {
	t        *testing.T
	svc      *CheckoutService
	listings *marketplace.EntListingService
	licenses *marketplace.EntLicenseService
	org      uuid.UUID
	buyer    uuid.UUID
	db       *ent.Client
}

func newWebhookFixture(t *testing.T) *webhookFixture {
	t.Helper()
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	org, err := db.Organization.Create().SetName("Buyer").SetSlug("buyer-" + uuid.NewString()[:8]).Save(ctx)
	if err != nil {
		t.Fatalf("organization: %v", err)
	}
	buyer, err := db.Principal.Create().SetType("human").SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("Buyer").Save(ctx)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	listings := marketplace.NewEntListingService(db, nil)
	licenses := marketplace.NewEntLicenseService(db, nil)
	return &webhookFixture{
		t: t, db: db, listings: listings, licenses: licenses, org: org.ID, buyer: buyer.ID,
		svc: NewCheckoutService(Config{WebhookSecret: testSecret}, listings, licenses, nil),
	}
}

func (f *webhookFixture) listing(model marketplace.PricingModel) uuid.UUID {
	f.t.Helper()
	ctx := context.Background()
	l := &marketplace.Listing{ID: uuid.New(), CreatorOrgID: f.org, OwnerID: f.buyer, ProductType: "course",
		Title: "Course", PricingModel: model, PriceCents: 1000, Currency: "usd"}
	if err := f.listings.Create(ctx, l); err != nil {
		f.t.Fatalf("listing: %v", err)
	}
	if err := f.listings.Publish(ctx, l.ID); err != nil {
		f.t.Fatalf("publish: %v", err)
	}
	return l.ID
}

// send delivers a signed event to the webhook handler.
func (f *webhookFixture) send(eventType string, object map[string]any) error {
	f.t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		f.t.Fatalf("marshal object: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"id": "evt_" + uuid.NewString(), "object": "event", "type": eventType,
		"api_version": stripe.APIVersion, "data": map[string]any{"object": json.RawMessage(raw)},
	})
	if err != nil {
		f.t.Fatalf("marshal event: %v", err)
	}
	signed := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: testSecret})
	return f.svc.ProcessWebhook(context.Background(), signed.Payload, signed.Header)
}

func (f *webhookFixture) session(listing uuid.UUID, paymentStatus string, extra map[string]string) map[string]any {
	md := map[string]string{"listing_id": listing.String(), "organization_id": f.org.String(), "purchaser_id": f.buyer.String()}
	for k, v := range extra {
		md[k] = v
	}
	return map[string]any{"id": "cs_" + uuid.NewString(), "object": "checkout.session", "payment_status": paymentStatus, "metadata": md}
}

func (f *webhookFixture) licensed(listing uuid.UUID) *marketplace.License {
	f.t.Helper()
	l, err := f.licenses.GetByListingAndOrg(context.Background(), listing, f.org)
	if errors.Is(err, marketplace.ErrLicenseNotFound) {
		return nil
	}
	if err != nil {
		f.t.Fatalf("GetByListingAndOrg: %v", err)
	}
	return l
}

func TestWebhookRejectsBadSignatures(t *testing.T) {
	f := newWebhookFixture(t)
	listing := f.listing(marketplace.PricingOneTime)
	payload, err := json.Marshal(map[string]any{"id": "evt_1", "object": "event", "type": "checkout.session.completed",
		"api_version": stripe.APIVersion, "data": map[string]any{"object": f.session(listing, "paid", nil)}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	other := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: "whsec_someone_else"}) //nolint:gosec // G101: a test-only secret
	for name, header := range map[string]string{"wrong secret": other.Header, "missing": "", "garbage": "t=1,v1=00"} {
		if err := f.svc.ProcessWebhook(context.Background(), payload, header); err == nil {
			t.Errorf("%s signature accepted", name)
		}
	}
	if f.licensed(listing) != nil {
		t.Error("a forged event granted a license")
	}
}

// Without a signing secret, an event signed with the empty key, which
// anyone can compute, must be refused.
func TestWebhookFailsClosedWithoutSecret(t *testing.T) {
	f := newWebhookFixture(t)
	f.svc = NewCheckoutService(Config{}, f.listings, f.licenses, nil)
	listing := f.listing(marketplace.PricingOneTime)
	payload, err := json.Marshal(map[string]any{"id": "evt_1", "object": "event", "type": "checkout.session.completed",
		"api_version": stripe.APIVersion, "data": map[string]any{"object": f.session(listing, "paid", nil)}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	forged := webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: payload, Secret: ""})

	if _, err := VerifyWebhook(forged.Payload, forged.Header, ""); !errors.Is(err, ErrWebhookSecretRequired) {
		t.Errorf("VerifyWebhook with no secret = %v, want ErrWebhookSecretRequired", err)
	}
	if err := f.svc.ProcessWebhook(context.Background(), forged.Payload, forged.Header); !errors.Is(err, ErrWebhookSecretRequired) {
		t.Errorf("ProcessWebhook with no secret = %v, want ErrWebhookSecretRequired", err)
	}
	if f.licensed(listing) != nil {
		t.Error("an event signed with the empty key granted a license")
	}
}

func TestCheckoutGrantsOnlyWhenPaid(t *testing.T) {
	f := newWebhookFixture(t)
	listing := f.listing(marketplace.PricingOneTime)

	// A delayed payment method completes checkout unpaid: no license yet.
	sess := f.session(listing, "unpaid", nil)
	if err := f.send("checkout.session.completed", sess); err != nil {
		t.Fatalf("completed unpaid: %v", err)
	}
	if f.licensed(listing) != nil {
		t.Fatal("license granted before payment")
	}

	// The payment succeeds later.
	sess["payment_status"] = "paid"
	if err := f.send("checkout.session.async_payment_succeeded", sess); err != nil {
		t.Fatalf("async payment succeeded: %v", err)
	}
	lic := f.licensed(listing)
	if lic == nil || lic.PurchasedBy != f.buyer || lic.LicenseType != marketplace.LicenseUnlimited {
		t.Fatalf("license = %+v", lic)
	}

	// Redelivery is harmless.
	if err := f.send("checkout.session.completed", sess); err != nil {
		t.Errorf("redelivered event: %v", err)
	}
}

func TestPerSeatCheckoutNeedsASeatCount(t *testing.T) {
	f := newWebhookFixture(t)
	listing := f.listing(marketplace.PricingPerSeat)
	for _, seats := range []string{"", "lots", "0", "-3"} {
		if err := f.send("checkout.session.completed", f.session(listing, "paid", map[string]string{"seats": seats})); err == nil {
			t.Errorf("seats %q accepted", seats)
		}
	}
	if f.licensed(listing) != nil {
		t.Fatal("a seat-based license was granted without a valid seat count")
	}
	if err := f.send("checkout.session.completed", f.session(listing, "paid", map[string]string{"seats": "12"})); err != nil {
		t.Fatalf("valid seats: %v", err)
	}
	if lic := f.licensed(listing); lic == nil || lic.Seats == nil || *lic.Seats != 12 || lic.LicenseType != marketplace.LicenseSeatBased {
		t.Errorf("license = %+v", lic)
	}
}

func TestSubscriptionCancellationRevokesTheLicense(t *testing.T) {
	f := newWebhookFixture(t)
	listing := f.listing(marketplace.PricingSubscription)
	sess := f.session(listing, "paid", nil)
	sess["subscription"] = "sub_123"
	if err := f.send("checkout.session.completed", sess); err != nil {
		t.Fatalf("completed: %v", err)
	}
	lic := f.licensed(listing)
	if lic == nil || lic.StripeSubscriptionID == nil || *lic.StripeSubscriptionID != "sub_123" {
		t.Fatalf("license = %+v", lic)
	}

	sub := map[string]any{"id": "sub_123", "object": "subscription", "status": "canceled"}
	if err := f.send("customer.subscription.deleted", sub); err != nil {
		t.Fatalf("subscription deleted: %v", err)
	}
	if f.licensed(listing) != nil {
		t.Error("license survives the subscription's cancellation")
	}
	// Redelivery and unknown subscriptions are harmless.
	if err := f.send("customer.subscription.deleted", sub); err != nil {
		t.Errorf("redelivered cancellation: %v", err)
	}
	if err := f.send("customer.subscription.deleted", map[string]any{"id": "sub_unknown", "object": "subscription"}); err != nil {
		t.Errorf("unknown subscription: %v", err)
	}
}

func TestUnhandledAndMalformedEvents(t *testing.T) {
	f := newWebhookFixture(t)
	if err := f.send("customer.created", map[string]any{"id": "cus_1", "object": "customer"}); err != nil {
		t.Errorf("unhandled event type: %v", err)
	}
	if err := f.send("checkout.session.completed", map[string]any{"id": "cs_1", "object": "checkout.session", "payment_status": "paid",
		"metadata": map[string]string{"listing_id": "not-a-uuid"}}); err == nil {
		t.Error("malformed metadata accepted")
	}
}
