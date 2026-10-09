package organization_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/organization"
)

// TestResponseHasEntitlementsAndNoPlan verifies that an organization
// response carries the configured entitlements and no plan.
func TestResponseHasEntitlementsAndNoPlan(t *testing.T) {
	ctx := context.Background()
	api := newOrgAPI(t)
	owner := newHuman(t, api.db, "o@example.com")
	org, err := api.svc.Create(ctx, organization.CreateOrganizationInput{Name: "A", Slug: "a-org", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	code, body := api.do(http.MethodGet, "/organizations/a-org", owner, nil)
	if code != http.StatusOK {
		t.Fatalf("get: %d %s", code, body)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := raw["plan"]; ok {
		t.Error("response still has plan")
	}
	if string(raw["entitlements"]) != "[]" {
		t.Errorf("entitlements = %s, want []", raw["entitlements"])
	}

	cfg := organization.DefaultAPIConfig()
	cfg.Authorizer = memberAuthorizer(api.svc)
	cfg.Entitlements = func(_ context.Context, id uuid.UUID) ([]organization.Entitlement, error) {
		if id != org.ID {
			t.Errorf("entitlements asked for %s, want %s", id, org.ID)
		}
		return []organization.Entitlement{{Source: organization.EntitlementSourceSubscription, Tier: "pro"}}, nil
	}
	api.h = organization.NewAPI(api.svc, cfg)
	code, body = api.do(http.MethodGet, "/organizations/a-org", owner, nil)
	if code != http.StatusOK {
		t.Fatalf("get: %d %s", code, body)
	}
	var got struct {
		Entitlements []organization.Entitlement `json:"entitlements"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Entitlements) != 1 || got.Entitlements[0].Tier != "pro" {
		t.Errorf("entitlements = %+v", got.Entitlements)
	}
}
