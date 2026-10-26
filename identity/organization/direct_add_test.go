package organization_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/organization"
)

// Adding a member directly enrolls a principal without its consent, so an
// organization admin may not add an arbitrary principal: only a platform
// administrator may, or whoever APIConfig.DirectAdd allows. Everyone else
// is invited.
func TestAddMemberDirectlyNeedsConsentPolicy(t *testing.T) {
	ctx := context.Background()
	platformAdmin := uuid.New()
	api := newOrgAPI(t, platformAdmin)
	owner := newHuman(t, api.db, "owner@example.com")
	stranger := newHuman(t, api.db, "stranger@example.com")
	if _, err := api.svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OwnerPrincipalID: &owner}); err != nil {
		t.Fatal(err)
	}
	add := func(as, who uuid.UUID) (int, []byte) {
		return api.do(http.MethodPost, "/organizations/acme/members", as, map[string]any{"principal_id": who.String(), "role": "member"})
	}
	ok := func(code int) bool { return code == http.StatusCreated || code == http.StatusOK }

	// The owner cannot enroll another tenant's principal, and an unknown
	// principal gets the same answer.
	if code, body := add(owner, stranger); code != http.StatusForbidden {
		t.Errorf("owner adds a stranger: %d %s", code, body)
	}
	if code, body := add(owner, uuid.New()); code != http.StatusForbidden {
		t.Errorf("owner adds an unknown principal: %d %s", code, body)
	}
	if code, body := add(platformAdmin, stranger); !ok(code) {
		t.Errorf("platform administrator adds: %d %s", code, body)
	}

	// An application may allow the principals the organization governs.
	governed := newHuman(t, api.db, "governed@example.com")
	cfg := organization.DefaultAPIConfig()
	cfg.Authorizer = memberAuthorizer(api.svc)
	cfg.DirectAdd = func(_ context.Context, caller, _, principalID uuid.UUID) (bool, error) {
		return caller == owner && principalID == governed, nil
	}
	api.h = organization.NewAPI(api.svc, cfg)
	if code, body := add(owner, governed); !ok(code) {
		t.Errorf("owner adds a governed principal: %d %s", code, body)
	}
	other := newHuman(t, api.db, "other@example.com")
	if code, body := add(owner, other); code != http.StatusForbidden {
		t.Errorf("owner adds an ungoverned principal: %d %s", code, body)
	}
}
