package systemauthsvc_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"

	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

const testPricing = `{
  "formatVersion": "1", "app": "boards", "currency": "usd", "defaultPlan": "free",
  "applications": [{ "id": "boards", "name": "Boards" }],
  "tiers": [{ "id": "free", "name": "Free", "rank": 1 }, { "id": "pro", "name": "Pro", "rank": 2 }],
  "plans": [
    { "id": "free", "name": "Free", "tier": "free", "selfServe": true },
    { "id": "pro", "name": "Pro", "tier": "pro", "selfServe": true,
      "prices": [{ "interval": "month", "amountCents": 900 }] }
  ],
  "entitlements": [
    { "tier": "free", "application": "boards", "seats": 1 },
    { "tier": "pro", "application": "boards", "seats": 5 }
  ]
}`

func pricing(t *testing.T) *pricingspec.Spec {
	t.Helper()
	spec, err := pricingspec.Load(strings.NewReader(testPricing))
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func billingService(t *testing.T, b *systemauth.BillingConfig) *systemauthsvc.Service {
	t.Helper()
	cfg := consoleConfig(t, "")
	cfg.Billing = b
	s, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{
		SigningKey: testKey(t), Logger: discardLogger(), Migrate: true, Pricing: pricing(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, s)
	return s
}

func serve(s *systemauthsvc.Service, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader("{}")))
	return rec
}

const orgBilling = "/console/api/v1/organizations/9b2f3c1e-0000-4000-8000-000000000001/billing"

func TestBillingFreeMode(t *testing.T) {
	s := billingService(t, &systemauth.BillingConfig{})
	if rec := serve(s, http.MethodGet, orgBilling); rec.Code != http.StatusUnauthorized {
		t.Errorf("the console's billing without a session: %d %s", rec.Code, rec.Body)
	}
	if rec := serve(s, http.MethodPost, systemauthsvc.BillingWebhookPath); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("free mode serves a webhook: %d", rec.Code)
	}
	if _, err := s.SyncPrices(t.Context(), true); !errors.Is(err, systemauthsvc.ErrBillingNotConfigured) {
		t.Errorf("syncing prices in free mode: %v", err)
	}
	plan, err := s.OrganizationPlan(t.Context(), [16]byte{1})
	if err != nil || plan.ID != "free" {
		t.Errorf("an organization's plan in free mode: %q %v", plan.ID, err)
	}
}

func TestBillingWithStripe(t *testing.T) {
	s := billingService(t, &systemauth.BillingConfig{
		StripeSecretKey: "sk_test_example", StripeWebhookSecrets: []string{"whsec_example"},
	})
	rec := serve(s, http.MethodPost, systemauthsvc.BillingWebhookPath)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an unsigned event: %d %s, want 400", rec.Code, rec.Body)
	}
	if rec := serve(s, http.MethodGet, orgBilling); rec.Code != http.StatusUnauthorized {
		t.Errorf("the console's billing without a session: %d", rec.Code)
	}
}

func TestBillingConfigErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		edit      func(*systemauthsvc.Config)
		noPricing bool
		want      error
	}{
		"no console": {
			edit: func(c *systemauthsvc.Config) { c.Console = nil },
			want: systemauth.ErrInvalidBillingConfig,
		},
		"a key without a webhook secret": {
			edit: func(c *systemauthsvc.Config) {
				c.Billing.StripeSecretKey = "sk_test_example"
				c.Billing.StripeWebhookSecrets = []string{""}
			},
			want: systemauth.ErrInvalidBillingConfig,
		},
		"no pricing spec": {edit: func(*systemauthsvc.Config) {}, noPricing: true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := consoleConfig(t, "")
			cfg.Billing = &systemauth.BillingConfig{}
			tc.edit(cfg)
			opts := systemauthsvc.Options{SigningKey: testKey(t), Logger: discardLogger(), Migrate: true}
			if !tc.noPricing {
				opts.Pricing = pricing(t)
			}
			_, err := systemauthsvc.New(t.Context(), cfg, opts)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("%v, want %v", err, tc.want)
			}
		})
	}
}
