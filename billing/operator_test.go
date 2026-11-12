package billing

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/payforge"
)

// TestOperatorPlanOutlastsBillingEvents checks that a plan the operator
// set is the organization's plan whatever billing events say, that
// checkout refuses to sell it another, and that clearing it returns the
// organization to its subscription's plan.
func TestOperatorPlanOutlastsBillingEvents(t *testing.T) {
	ctx := context.Background()
	r := newConsoleRig(t, true)
	planOf := func() string {
		t.Helper()
		p, _, err := OrganizationPlan(ctx, r.db, r.spec, r.buyer, true)
		if err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	apply := func(status string) {
		t.Helper()
		if err := r.sink.Apply(ctx, payforge.Entitlement{
			Subject: r.buyer.String(), Plan: "pro", Status: status, SubscriptionID: "sub_1", CustomerID: "cus_1",
			ValidUntil: time.Now().Add(30 * 24 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := SetOperatorPlan(ctx, r.db, r.spec, r.buyer, "staff", "  runs the service "); err != nil {
		t.Fatal(err)
	}
	if got := planOf(); got != "staff" {
		t.Fatalf("an organization that never subscribed: plan %q, want staff", got)
	}
	if p, _, err := OrganizationPlan(ctx, r.db, r.spec, r.buyer, false); err != nil || p.ID != "staff" {
		t.Errorf("free mode: plan %q %v, want the operator's staff", p.ID, err)
	}
	op, set, err := OperatorPlanOf(ctx, r.db, r.buyer)
	if err != nil || !set || op.Plan != "staff" || op.Note != "runs the service" || op.SetAt.IsZero() {
		t.Fatalf("operator plan: %+v %v %v", op, set, err)
	}

	_, out := r.do(t, http.MethodGet, r.buyer, "", "")
	if out["plan"] != "staff" || out["setByOperator"] != true {
		t.Errorf("console status: %v", out)
	}
	plans := out["pricing"].(map[string]any)["plans"].([]any) //nolint:forcetypeassert // JSON
	if len(plans) != 3 {
		t.Errorf("the pricing view shows the internal plan: %v", plans)
	}
	if code, out := r.do(t, http.MethodPost, r.buyer, "/checkout", `{"plan":"pro","interval":"month"}`); code != http.StatusConflict {
		t.Errorf("checkout with an operator's plan: %d %v", code, out)
	}
	if len(r.provider.plans) != 0 {
		t.Errorf("checkout reached the provider: %v", r.provider.plans)
	}

	apply("active")
	if got := planOf(); got != "staff" {
		t.Errorf("after a paid subscription: plan %q, want staff", got)
	}
	cleared, err := ClearOperatorPlan(ctx, r.db, r.buyer)
	if err != nil || !cleared {
		t.Fatalf("clear: %v %v", cleared, err)
	}
	if got := planOf(); got != "pro" {
		t.Errorf("cleared: plan %q, want the subscription's pro", got)
	}
	if _, out := r.do(t, http.MethodGet, r.buyer, "", ""); out["setByOperator"] != nil {
		t.Errorf("cleared, the console still says the operator set it: %v", out)
	}

	if err := SetOperatorPlan(ctx, r.db, r.spec, r.buyer, "enterprise", ""); err != nil {
		t.Fatal(err)
	}
	apply("canceled")
	if got := planOf(); got != "enterprise" {
		t.Errorf("after the subscription is canceled: plan %q, want enterprise", got)
	}
	if _, err := ClearOperatorPlan(ctx, r.db, r.buyer); err != nil {
		t.Fatal(err)
	}
	if got := planOf(); got != "free" {
		t.Errorf("cleared after cancellation: plan %q, want the default", got)
	}
	if cleared, err := ClearOperatorPlan(ctx, r.db, r.buyer); err != nil || cleared {
		t.Errorf("clear with none set: %v %v", cleared, err)
	}
}

func TestOperatorPlanRefusesBadInput(t *testing.T) {
	ctx := context.Background()
	r := newCheckoutRig(t)
	for name, tc := range map[string]struct {
		org  uuid.UUID
		plan string
		note string
		want error
	}{
		"plan not in the spec": {r.buyer, "platinum", "", ErrUnknownPlan},
		"no organization":      {uuid.New(), "staff", "", ErrUnknownOrganization},
		"long note":            {r.buyer, "staff", strings.Repeat("a", MaxOperatorNote+1), ErrInvalidNote},
		"two-line note":        {r.buyer, "staff", "one\ntwo", ErrInvalidNote},
	} {
		if err := SetOperatorPlan(ctx, r.db, r.spec, tc.org, tc.plan, tc.note); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if _, set, err := OperatorPlanOf(ctx, r.db, r.buyer); err != nil || set {
		t.Errorf("a refused plan was stored: %v %v", set, err)
	}

	// The limit counts characters, so a note of multibyte characters at
	// the limit is stored, though it is longer in bytes.
	note := strings.Repeat("é", MaxOperatorNote)
	if err := SetOperatorPlan(ctx, r.db, r.spec, r.buyer, "staff", note); err != nil {
		t.Fatalf("a %d-character note: %v", MaxOperatorNote, err)
	}
	if op, _, err := OperatorPlanOf(ctx, r.db, r.buyer); err != nil || op.Note != note {
		t.Errorf("the note read back: %v", err)
	}
}

func TestOperatorPlansLists(t *testing.T) {
	ctx := context.Background()
	r := newCheckoutRig(t)
	if err := SetOperatorPlan(ctx, r.db, r.spec, r.seller, "staff", "first"); err != nil {
		t.Fatal(err)
	}
	if err := SetOperatorPlan(ctx, r.db, r.spec, r.buyer, "enterprise", "second"); err != nil {
		t.Fatal(err)
	}
	got, err := OperatorPlans(ctx, r.db)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].OrganizationID != r.seller || got[1].Plan != "enterprise" || got[1].Note != "second" {
		t.Errorf("operator plans: %+v", got)
	}
}
