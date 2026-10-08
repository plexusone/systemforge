package marketplace

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/simple"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

type fakeCheckout struct {
	got *CheckoutRequest
}

func (f *fakeCheckout) CreateCheckoutSession(_ context.Context, req CheckoutRequest) (*CheckoutSession, error) {
	f.got = &req
	return &CheckoutSession{SessionID: "cs_test", URL: "https://checkout.example/cs_test"}, nil
}

func (f *fakeCheckout) ProcessWebhook(context.Context, []byte, string) error { return nil }

type fakeService struct{ checkout CheckoutService }

func (s fakeService) Listings() ListingService           { return nil }
func (s fakeService) Licenses() LicenseService           { return nil }
func (s fakeService) Subscriptions() SubscriptionService { return nil }
func (s fakeService) Checkout() CheckoutService          { return s.checkout }

const principalHeader = "X-Test-Principal"

// newCheckoutAPI serves the marketplace API with a test middleware that
// authenticates the principal named in principalHeader, as
// requestprincipal.Middleware would.
func newCheckoutAPI(t *testing.T, opts ...APIOption) (humatest.TestAPI, *fakeCheckout) {
	t.Helper()
	_, api := humatest.New(t)
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		if id := ctx.Header(principalHeader); id != "" {
			ctx = huma.WithContext(ctx, requestprincipal.WithPrincipal(ctx.Context(), &requestprincipal.RequestPrincipal{PrincipalID: id}))
		}
		next(ctx)
	})
	fc := &fakeCheckout{}
	NewAPI(api, APIConfig{}, fakeService{checkout: fc}, opts...)
	return api, fc
}

func TestCheckoutActsForTheAuthenticatedCaller(t *testing.T) {
	owner, member, stranger := uuid.New(), uuid.New(), uuid.New()
	org := uuid.New()
	roles := map[uuid.UUID]string{owner: "owner", member: "member"}
	orgs := simple.New(simple.WithRoleGetter(func(_ context.Context, pid, oid uuid.UUID) (string, error) {
		if oid != org {
			return "", nil
		}
		return roles[pid], nil
	}))
	api, fc := newCheckoutAPI(t, WithPurchaseAuthorizer(OrgRolePurchaseAuthorizer(orgs)))

	body := func(purchaser string) map[string]any {
		b := map[string]any{
			"listing_id":      uuid.NewString(),
			"organization_id": org.String(),
			"success_url":     "https://app.example.com/ok",
			"cancel_url":      "https://app.example.com/cancel",
		}
		if purchaser != "" {
			b["purchaser_id"] = purchaser
		}
		return b
	}
	as := func(who uuid.UUID) string { return principalHeader + ": " + who.String() }

	// The owner buys; the purchaser is the caller, not a body field.
	resp := api.Post("/checkout", as(owner), body(""))
	if resp.Code != http.StatusOK {
		t.Fatalf("owner checkout: %d %s", resp.Code, resp.Body)
	}
	if fc.got == nil || fc.got.PurchaserID != owner || fc.got.OrganizationID != org {
		t.Errorf("checkout request = %+v", fc.got)
	}
	// The deprecated field is accepted when it names the caller.
	if resp := api.Post("/checkout", as(owner), body(owner.String())); resp.Code != http.StatusOK {
		t.Errorf("matching purchaser_id: %d %s", resp.Code, resp.Body)
	}

	for _, tc := range []struct {
		name    string
		headers []any
		body    map[string]any
		want    int
	}{
		{"unauthenticated", nil, body(""), http.StatusUnauthorized},
		{"foreign subject", []any{principalHeader + ": https://issuer.example|abc"}, body(""), http.StatusUnauthorized},
		{"impersonation", []any{as(stranger)}, body(owner.String()), http.StatusForbidden},
		{"member", []any{as(member)}, body(""), http.StatusForbidden},
		{"non-member", []any{as(stranger)}, body(""), http.StatusForbidden},
	} {
		fc.got = nil
		args := append(append([]any{}, tc.headers...), tc.body)
		resp := api.Post("/checkout", args...)
		if resp.Code != tc.want {
			t.Errorf("%s: status %d, want %d (%s)", tc.name, resp.Code, tc.want, resp.Body)
		}
		if fc.got != nil {
			t.Errorf("%s: reached checkout as %v", tc.name, fc.got.PurchaserID)
		}
	}
}

// TestCheckoutRequiresPurchaseAuthorizer verifies that checkout fails
// closed when no purchase authorizer is configured.
func TestCheckoutRequiresPurchaseAuthorizer(t *testing.T) {
	api, fc := newCheckoutAPI(t)
	resp := api.Post("/checkout", principalHeader+": "+uuid.NewString(), map[string]any{
		"listing_id": uuid.NewString(), "organization_id": uuid.NewString(),
		"success_url": "https://app.example.com/ok", "cancel_url": "https://app.example.com/cancel",
	})
	if resp.Code != http.StatusNotImplemented || fc.got != nil {
		t.Errorf("status %d, reached checkout %v", resp.Code, fc.got != nil)
	}
}

func TestCheckoutAuthorizerAndResolverErrors(t *testing.T) {
	boom := errors.New("backend down")
	org := uuid.New()
	payload := map[string]any{
		"listing_id": uuid.NewString(), "organization_id": org.String(),
		"success_url": "https://app.example.com/ok", "cancel_url": "https://app.example.com/cancel",
	}

	api, fc := newCheckoutAPI(t, WithPurchaseAuthorizer(PurchaseAuthorizerFunc(
		func(context.Context, uuid.UUID, uuid.UUID) (bool, error) { return false, boom })))
	if resp := api.Post("/checkout", principalHeader+": "+uuid.NewString(), payload); resp.Code != http.StatusInternalServerError || fc.got != nil {
		t.Errorf("authorizer error: %d", resp.Code)
	}

	fixed := uuid.New()
	api, fc = newCheckoutAPI(t,
		WithCallerResolver(func(context.Context) (uuid.UUID, error) { return fixed, nil }),
		WithPurchaseAuthorizer(PurchaseAuthorizerFunc(func(_ context.Context, p, o uuid.UUID) (bool, error) { return p == fixed && o == org, nil })))
	if resp := api.Post("/checkout", payload); resp.Code != http.StatusOK || fc.got == nil || fc.got.PurchaserID != fixed {
		t.Errorf("custom resolver: %d %+v", resp.Code, fc.got)
	}
}

func TestOrgRolePurchaseAuthorizerRoles(t *testing.T) {
	ctx := context.Background()
	p, org := uuid.New(), uuid.New()
	role := "admin"
	orgs := simple.New(simple.WithRoleGetter(func(context.Context, uuid.UUID, uuid.UUID) (string, error) { return role, nil }))
	if ok, err := OrgRolePurchaseAuthorizer(orgs).CanPurchase(ctx, p, org); err != nil || !ok {
		t.Errorf("admin default = %v, %v", ok, err)
	}
	if ok, err := OrgRolePurchaseAuthorizer(orgs, "owner").CanPurchase(ctx, p, org); err != nil || ok {
		t.Errorf("admin with owner-only = %v, %v", ok, err)
	}
	var _ authz.OrgAuthorizer = orgs
}
