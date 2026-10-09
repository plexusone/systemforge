package organization_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/organization"
)

type apiVocab struct{}

func (apiVocab) App() string { return "alpha" }
func (apiVocab) Roles() authz.RolePermissions {
	return authz.RolePermissions{"viewer": {"item.read"}, "admin": {"item.read", "app.admin"}}
}
func (apiVocab) Hierarchy() authz.RoleHierarchy {
	return authz.RoleHierarchy{"viewer": 10, "admin": 40}
}
func (apiVocab) Scopes() []string      { return []string{"alpha:admin"} }
func (apiVocab) SpiceDBSchema() string { return "" }

func TestAppRoleEndpoints(t *testing.T) {
	ctx := context.Background()
	api := newOrgAPI(t)
	owner := newHuman(t, api.db, "o@example.com")
	member := newHuman(t, api.db, "m@example.com")
	other := newHuman(t, api.db, "x@example.com")
	if _, err := api.svc.Create(ctx, organization.CreateOrganizationInput{Name: "A", Slug: "a-org", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	org, err := api.svc.GetBySlug(ctx, "a-org")
	if err != nil {
		t.Fatalf("GetBySlug: %v", err)
	}
	for _, id := range []uuid.UUID{member, other} {
		if _, err := api.svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: id, Role: organization.RoleMember}); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
	}

	path := "/organizations/a-org/members/" + member.String() + "/app-roles"

	// Without the service the endpoints answer 501.
	if code, _ := api.do(http.MethodGet, "/organizations/a-org/app-roles", owner, nil); code != http.StatusNotImplemented {
		t.Fatalf("unconfigured list: %d", code)
	}

	reg := authz.NewVocabularyRegistry()
	if err := reg.Register(apiVocab{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	cfg := organization.DefaultAPIConfig()
	cfg.Authorizer = memberAuthorizer(api.svc)
	cfg.AppRoles = approle.NewService(api.db, reg, approle.EntitleAll(reg))
	api.h = organization.NewAPI(api.svc, cfg)

	// A member may not assign roles.
	if code, _ := api.do(http.MethodPut, path+"/alpha", member, map[string]string{"role": "admin"}); code != http.StatusForbidden {
		t.Errorf("member assigns: %d, want 403", code)
	}
	// The owner assigns, then changes.
	if code, body := api.do(http.MethodPut, path+"/alpha", owner, map[string]string{"role": "viewer"}); code != http.StatusOK {
		t.Fatalf("assign: %d %s", code, body)
	}
	code, body := api.do(http.MethodPut, path+"/alpha", owner, map[string]string{"role": "admin"})
	if code != http.StatusOK {
		t.Fatalf("change: %d %s", code, body)
	}
	var set organization.AppRoleResponse
	if err := json.Unmarshal(body, &set); err != nil || set.Role != "admin" || set.Application != "alpha" {
		t.Errorf("change response = %+v, %v", set, err)
	}
	// Invalid role and application.
	if code, _ := api.do(http.MethodPut, path+"/alpha", owner, map[string]string{"role": "root"}); code != http.StatusBadRequest {
		t.Errorf("unknown role: %d, want 400", code)
	}
	if code, _ := api.do(http.MethodPut, path+"/nope", owner, map[string]string{"role": "viewer"}); code != http.StatusBadRequest {
		t.Errorf("unknown application: %d, want 400", code)
	}

	// The member reads their own roles; another member may not.
	code, body = api.do(http.MethodGet, path, member, nil)
	if code != http.StatusOK {
		t.Fatalf("own roles: %d %s", code, body)
	}
	var own struct {
		AppRoles  []organization.AppRoleResponse `json:"app_roles"`
		Effective map[string]string              `json:"effective"`
	}
	if err := json.Unmarshal(body, &own); err != nil || len(own.AppRoles) != 1 || own.Effective["alpha"] != "admin" {
		t.Errorf("own roles = %+v, %v", own, err)
	}
	if code, _ := api.do(http.MethodGet, path, other, nil); code != http.StatusForbidden {
		t.Errorf("other member reads: %d, want 403", code)
	}
	if code, _ := api.do(http.MethodGet, "/organizations/a-org/app-roles?application=alpha", owner, nil); code != http.StatusOK {
		t.Errorf("owner lists: %d", code)
	}

	// Removal.
	if code, body := api.do(http.MethodDelete, path+"/alpha", owner, nil); code != http.StatusNoContent {
		t.Fatalf("remove: %d %s", code, body)
	}
	if code, _ := api.do(http.MethodDelete, path+"/alpha", owner, nil); code != http.StatusNotFound {
		t.Errorf("second remove: %d, want 404", code)
	}
}
