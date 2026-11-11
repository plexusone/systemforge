package billing

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/payforge"
)

var errNoSession = errors.New("no session")

// consoleRig is the console's billing section over the fixture, with the
// purchaser holding role in the buying organization.
type consoleRig struct {
	*checkoutRig
	role     string
	signedIn bool
	h        http.Handler
}

func newConsoleRig(t *testing.T, paid bool) *consoleRig {
	t.Helper()
	r := &consoleRig{checkoutRig: newCheckoutRig(t), role: "owner", signedIn: true}
	cfg := ConsoleConfig{
		Spec: r.spec, DB: r.db, Mode: "test",
		Principal: func(*http.Request) (uuid.UUID, error) {
			if !r.signedIn {
				return uuid.Nil, errNoSession
			}
			return r.purchaser, nil
		},
		WriteAuthError: func(w http.ResponseWriter, _ error) {
			writeConsoleJSON(w, http.StatusUnauthorized, map[string]string{"error": "sign in required"})
		},
		Role: func(_ context.Context, principal, org uuid.UUID) (string, error) {
			if principal != r.purchaser || org != r.buyer {
				return "", nil
			}
			return r.role, nil
		},
	}
	if paid {
		co := r.config()
		co.URLs = RedirectURLs{
			PlanSuccess:  "https://app.example.com/orgs/" + OrganizationPlaceholder + "/billing?checkout=success",
			PlanCancel:   "https://app.example.com/orgs/" + OrganizationPlaceholder + "/billing",
			PortalReturn: "https://app.example.com/orgs/" + OrganizationPlaceholder + "/billing",
		}
		co.Listings, co.Purchasers = nil, nil
		cfg.Checkout = &co
	}
	h, err := NewConsole(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.h = h
	return r
}

func (r *consoleRig) do(t *testing.T, method string, org uuid.UUID, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, "/api/v1/organizations/"+org.String()+"/billing"+path, strings.NewReader(body))
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: %d %q: %v", method, path, w.Code, w.Body.String(), err)
	}
	return w.Code, out
}

func TestConsoleStatus(t *testing.T) {
	r := newConsoleRig(t, true)
	code, out := r.do(t, http.MethodGet, r.buyer, "", "")
	if code != http.StatusOK || out["plan"] != "free" || out["configured"] != true || out["mode"] != "test" || out["canManage"] != true {
		t.Fatalf("status: %d %v", code, out)
	}
	if out["subscription"] != nil {
		t.Errorf("an organization that never subscribed has a subscription: %v", out["subscription"])
	}
	plans := out["pricing"].(map[string]any)["plans"].([]any) //nolint:forcetypeassert // JSON
	if len(plans) != 3 {
		t.Errorf("pricing plans: %v", plans)
	}

	r.role = "member"
	if _, out := r.do(t, http.MethodGet, r.buyer, "", ""); out["canManage"] != false {
		t.Errorf("a member can manage billing: %v", out)
	}

	err := r.sink.Apply(context.Background(), payforge.Entitlement{
		Subject: r.buyer.String(), Plan: "pro", Status: "active", SubscriptionID: "sub_1", CustomerID: "cus_1",
		ValidUntil: time.Now().Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, out = r.do(t, http.MethodGet, r.buyer, "", "")
	sub, _ := out["subscription"].(map[string]any)
	if out["plan"] != "pro" || sub["paid"] != true || sub["status"] != "active" {
		t.Errorf("after a paid subscription: %v", out)
	}
}

func TestConsoleInFreeModeManagesNothing(t *testing.T) {
	r := newConsoleRig(t, false)
	code, out := r.do(t, http.MethodGet, r.buyer, "", "")
	if code != http.StatusOK || out["configured"] != false || out["canManage"] != false || out["plan"] != "free" {
		t.Fatalf("free mode status: %d %v", code, out)
	}
	if err := r.sink.Apply(context.Background(), payforge.Entitlement{
		Subject: r.buyer.String(), Plan: "pro", Status: "active", SubscriptionID: "sub_1", CustomerID: "cus_1",
		ValidUntil: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, out := r.do(t, http.MethodGet, r.buyer, "", ""); out["plan"] != "free" || out["subscription"] == nil {
		t.Errorf("free mode with a stored pro subscription: %v", out)
	}
}

func TestConsoleRefusesOutsiders(t *testing.T) {
	r := newConsoleRig(t, true)
	if code, _ := r.do(t, http.MethodGet, r.seller, "", ""); code != http.StatusNotFound {
		t.Errorf("another organization's billing: %d", code)
	}
	if code, _ := r.do(t, http.MethodPost, r.seller, "/checkout", `{"plan":"pro","interval":"month"}`); code != http.StatusNotFound {
		t.Errorf("checkout for another organization: %d", code)
	}
	r.signedIn = false
	if code, _ := r.do(t, http.MethodGet, r.buyer, "", ""); code != http.StatusUnauthorized {
		t.Errorf("without a session: %d", code)
	}
}

func TestConsoleCheckoutAndPortal(t *testing.T) {
	r := newConsoleRig(t, true)
	r.role = "member"
	if code, _ := r.do(t, http.MethodPost, r.buyer, "/checkout", `{"plan":"pro","interval":"month"}`); code != http.StatusForbidden {
		t.Errorf("a member started a checkout: %d", code)
	}
	r.role = "admin"
	code, out := r.do(t, http.MethodPost, r.buyer, "/checkout", `{"plan":"pro","interval":"month"}`)
	if code != http.StatusOK || out["url"] != "https://checkout.example/plan" {
		t.Fatalf("checkout: %d %v", code, out)
	}
	got := r.provider.plans[len(r.provider.plans)-1]
	if want := "https://app.example.com/orgs/" + r.buyer.String() + "/billing?checkout=success"; got.SuccessURL != want || got.Subject.ID != r.buyer.String() {
		t.Errorf("checkout for %s returns to %q, want %q", got.Subject.ID, got.SuccessURL, want)
	}

	code, out = r.do(t, http.MethodPost, r.buyer, "/portal", "")
	if code != http.StatusOK || out["url"] != "https://portal.example/session" {
		t.Fatalf("portal: %d %v", code, out)
	}
	if want := "cus_" + r.buyer.String() + " https://app.example.com/orgs/" + r.buyer.String() + "/billing"; r.provider.portals[0] != want {
		t.Errorf("portal %q, want %q", r.provider.portals[0], want)
	}
}

func TestConsoleFreeMode(t *testing.T) {
	r := newConsoleRig(t, false)
	code, out := r.do(t, http.MethodGet, r.buyer, "", "")
	if code != http.StatusOK || out["configured"] != false || out["plan"] != "free" {
		t.Fatalf("free mode status: %d %v", code, out)
	}
	if code, _ := r.do(t, http.MethodPost, r.buyer, "/checkout", `{"plan":"pro","interval":"month"}`); code != http.StatusConflict {
		t.Errorf("checkout in free mode: %d", code)
	}
}

func TestOrganizationPlanFollowsTheSubscription(t *testing.T) {
	r := newConsoleRig(t, false)
	ctx := context.Background()
	apply := func(status string) {
		t.Helper()
		if err := r.sink.Apply(ctx, payforge.Entitlement{
			Subject: r.buyer.String(), Plan: "pro", Status: status, SubscriptionID: "sub_1", CustomerID: "cus_1",
			ValidUntil: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	for status, want := range map[string]string{"trialing": "pro", "past_due": "pro", "canceled": "free", "active": "pro"} {
		apply(status)
		plan, _, err := OrganizationPlan(ctx, r.db, r.spec, r.buyer, true)
		if err != nil {
			t.Fatal(err)
		}
		if plan.ID != want {
			t.Errorf("%s: plan %q, want %q", status, plan.ID, want)
		}
	}
	// In free mode a stored subscription grants nothing.
	plan, sub, err := OrganizationPlan(ctx, r.db, r.spec, r.buyer, false)
	if err != nil || plan.ID != "free" || sub == nil || sub.PlanTier != "pro" {
		t.Errorf("free mode with an active pro subscription: %q %+v %v", plan.ID, sub, err)
	}
}
