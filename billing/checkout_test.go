package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/plexusone/payforge"
	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"

	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/marketplace"
)

// fakeProvider stands in for payforge's Stripe client.
type fakeProvider struct {
	err     error
	plans   []payforge.PlanCheckout
	sales   []payforge.Sale
	portals []string
}

func (p *fakeProvider) Enabled() bool                { return true }
func (p *fakeProvider) Plan(string) pricingspec.Plan { return pricingspec.Plan{} }
func (p *fakeProvider) EnsureCustomer(_ context.Context, s payforge.Subject) (string, error) {
	return "cus_" + s.ID, nil
}
func (p *fakeProvider) CheckoutPlan(_ context.Context, c payforge.PlanCheckout) (payforge.Session, error) {
	if p.err != nil {
		return payforge.Session{}, p.err
	}
	p.plans = append(p.plans, c)
	return payforge.Session{ID: "cs_plan", URL: "https://checkout.example/plan"}, nil
}
func (p *fakeProvider) CheckoutProduct(context.Context, payforge.ProductCheckout) (payforge.Session, error) {
	return payforge.Session{}, errors.New("not used")
}
func (p *fakeProvider) Portal(_ context.Context, customer, returnURL string) (string, error) {
	p.portals = append(p.portals, customer+" "+returnURL)
	return "https://portal.example/session", nil
}
func (p *fakeProvider) CreateAccount(context.Context, payforge.Subject, string) (string, error) {
	return "", errors.New("not used")
}
func (p *fakeProvider) OnboardingLink(context.Context, string, string, string) (string, error) {
	return "", errors.New("not used")
}
func (p *fakeProvider) Account(context.Context, string) (payforge.AccountState, error) {
	return payforge.AccountState{}, errors.New("not used")
}
func (p *fakeProvider) CheckoutSale(_ context.Context, s payforge.Sale) (payforge.Session, error) {
	if p.err != nil {
		return payforge.Session{}, p.err
	}
	p.sales = append(p.sales, s)
	return payforge.Session{ID: "cs_sale", URL: "https://checkout.example/sale"}, nil
}

var testURLs = RedirectURLs{
	PlanSuccess: "https://app.example.com/billing/done", PlanCancel: "https://app.example.com/pricing",
	ListingSuccess: "https://app.example.com/market/done", ListingCancel: "https://app.example.com/market",
	PortalReturn: "https://app.example.com/billing",
}

type checkoutRig struct {
	*fixture
	provider *fakeProvider
	spec     *pricingspec.Spec
	co       *Checkout
	allowed  bool
	managed  bool
	logs     *bytes.Buffer
}

func newCheckoutRig(t *testing.T) *checkoutRig {
	t.Helper()
	r := &checkoutRig{fixture: newFixture(t), provider: &fakeProvider{}, spec: loadSpec(t), allowed: true, logs: &bytes.Buffer{}}
	co, err := NewCheckout(r.config())
	if err != nil {
		t.Fatal(err)
	}
	r.co = co
	return r
}

func (r *checkoutRig) config() CheckoutConfig {
	return CheckoutConfig{
		Billing: r.provider, Connect: r.provider, Spec: r.spec, Store: r.store, DB: r.db,
		Listings: marketplace.NewEntListingService(r.db, nil), ListingProduct: "listing",
		Purchases: marketplace.PurchaseAuthorizerFunc(func(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
			return r.allowed, nil
		}),
		Purchasers:      managedFunc(func() bool { return r.managed }),
		Locker:          &payforge.MemoryLocker{},
		URLs:            testURLs,
		AllowedURLHosts: []string{"app.example.com"},
		Logger:          slog.New(slog.NewTextHandler(r.logs, nil)),
	}
}

type managedFunc func() bool

func (f managedFunc) IsManaged(context.Context, uuid.UUID) (bool, error) { return f(), nil }

// call posts body to handler as the purchaser acting for org; a nil org
// means the credential names none, and anonymous means no caller at all.
func (r *checkoutRig) call(h http.Handler, org *uuid.UUID, body string) (int, map[string]string) {
	req := httptest.NewRequest(http.MethodPost, "/billing/x", strings.NewReader(body))
	p := &requestprincipal.RequestPrincipal{PrincipalID: r.purchaser.String()}
	if org != nil {
		p.Organization = org.String()
	}
	req = req.WithContext(requestprincipal.WithPrincipal(req.Context(), p))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		panic(err)
	}
	return w.Code, out
}

func TestNewCheckoutChecksConfig(t *testing.T) {
	r := newCheckoutRig(t)
	cfg := r.config()
	cfg.Purchases = nil
	if _, err := NewCheckout(cfg); err == nil {
		t.Fatal("a checkout without a purchase authorizer was accepted")
	}
	for _, bad := range []string{"https://evil.example/x", "http://app.example.com/x", "/relative", "https://user@app.example.com/"} {
		cfg := r.config()
		cfg.URLs.PlanSuccess = bad
		if _, err := NewCheckout(cfg); err == nil {
			t.Fatalf("redirect %q was accepted", bad)
		}
	}
	cfg = r.config()
	cfg.URLs.PortalReturn = "http://localhost:8080/billing"
	if _, err := NewCheckout(cfg); err != nil {
		t.Fatalf("localhost: %v", err)
	}
}

func TestCheckoutRefusesWithoutAuthorization(t *testing.T) {
	r := newCheckoutRig(t)
	h := r.co.PlanHandler()
	body := `{"plan":"pro","interval":"month"}`

	anon := httptest.NewRecorder()
	h.ServeHTTP(anon, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	if anon.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", anon.Code)
	}
	if code, _ := r.call(h, nil, body); code != http.StatusBadRequest {
		t.Fatalf("no organization: %d", code)
	}
	r.allowed = false
	if code, out := r.call(h, &r.buyer, body); code != http.StatusForbidden || out["error"] == "" {
		t.Fatalf("not allowed: %d %v", code, out)
	}
	r.allowed, r.managed = true, true
	if code, _ := r.call(h, &r.buyer, body); code != http.StatusForbidden {
		t.Fatalf("managed: %d", code)
	}
	if len(r.provider.plans) != 0 {
		t.Fatal("a refused request reached the provider")
	}
}

func TestPlanCheckout(t *testing.T) {
	ctx := context.Background()
	r := newCheckoutRig(t)
	h := r.co.PlanHandler()

	code, out := r.call(h, &r.buyer, `{"plan":"pro","interval":"month"}`)
	if code != http.StatusOK || out["url"] != "https://checkout.example/plan" {
		t.Fatalf("%d %v", code, out)
	}
	got := r.provider.plans[0]
	if got.Subject.ID != r.buyer.String() || got.Subject.Name != "buyer" || got.SuccessURL != testURLs.PlanSuccess || got.CancelURL != testURLs.PlanCancel {
		t.Fatalf("checkout = %+v", got)
	}
	if org, err := r.store.SubjectForCustomer(ctx, "cus_"+r.buyer.String()); err != nil || org != r.buyer.String() {
		t.Fatalf("customer not linked: %q %v", org, err)
	}

	// Redirect URLs cannot come from the request.
	if code, _ := r.call(h, &r.buyer, `{"plan":"pro","interval":"month","success_url":"https://evil.example"}`); code != http.StatusBadRequest {
		t.Fatalf("a request URL was accepted: %d", code)
	}

	r.provider.err = payforge.ErrAlreadySubscribed
	if code, _ := r.call(h, &r.buyer, `{"plan":"pro","interval":"month"}`); code != http.StatusConflict {
		t.Fatalf("already subscribed: %d", code)
	}
	r.provider.err = errors.New("stripe: card_error secret detail")
	code, out = r.call(h, &r.buyer, `{"plan":"pro","interval":"month"}`)
	if code != http.StatusBadGateway || strings.Contains(out["error"], "secret") {
		t.Fatalf("provider failure: %d %v", code, out)
	}
	if !strings.Contains(r.logs.String(), "secret detail") {
		t.Fatal("the cause was not logged")
	}
}

func TestPortal(t *testing.T) {
	ctx := context.Background()
	r := newCheckoutRig(t)
	h := r.co.PortalHandler()
	if code, _ := r.call(h, &r.buyer, ``); code != http.StatusNotFound {
		t.Fatalf("no customer: %d", code)
	}
	if err := r.store.LinkCustomer(ctx, "cus_9", r.buyer); err != nil {
		t.Fatal(err)
	}
	code, out := r.call(h, &r.buyer, ``)
	if code != http.StatusOK || out["url"] != "https://portal.example/session" {
		t.Fatalf("%d %v", code, out)
	}
	if r.provider.portals[0] != "cus_9 "+testURLs.PortalReturn {
		t.Fatalf("portal = %q", r.provider.portals[0])
	}
}

func TestListingCheckout(t *testing.T) {
	ctx := context.Background()
	r := newCheckoutRig(t)
	h := r.co.ListingHandler()
	body := `{"listing_id":"` + r.listing.String() + `"}`

	if code, _ := r.call(h, &r.buyer, body); code != http.StatusConflict {
		t.Fatalf("seller without an account: %d", code)
	}
	if err := r.sink.ApplySeller(ctx, payforge.SellerAccount{Subject: r.seller.String(), AccountID: "acct_1", ChargesEnabled: true}); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.call(h, &r.seller, body); code != http.StatusBadRequest {
		t.Fatalf("own listing: %d", code)
	}
	if code, _ := r.call(h, &r.buyer, `{"listing_id":"`+uuid.NewString()+`"}`); code != http.StatusNotFound {
		t.Fatalf("unknown listing: %d", code)
	}

	code, out := r.call(h, &r.buyer, body)
	if code != http.StatusOK || out["url"] != "https://checkout.example/sale" {
		t.Fatalf("%d %v", code, out)
	}
	sale := r.provider.sales[0]
	if sale.SellerAccount != "acct_1" || sale.AmountCents != 2500 || sale.Product != "listing" || sale.SellerPlan != "free" ||
		sale.Buyer.ID != r.buyer.String() || sale.SuccessURL != testURLs.ListingSuccess {
		t.Fatalf("sale = %+v", sale)
	}

	// The recorded order lets the paid checkout grant the license.
	ev := payforge.Event{ID: "evt_9", Kind: payforge.EventCheckoutCompleted, Subject: r.buyer.String(),
		Checkout: &payforge.CheckoutResult{SessionID: "cs_sale", Mode: "payment", Paid: true, PaymentIntent: "pi_9"}}
	if err := r.sink.CompleteCheckout(ctx, ev); err != nil {
		t.Fatal(err)
	}
	r.expect(t, true)
	if code, _ := r.call(h, &r.buyer, body); code != http.StatusConflict {
		t.Fatalf("already licensed: %d", code)
	}
}
