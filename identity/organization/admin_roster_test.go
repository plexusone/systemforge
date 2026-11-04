package organization_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/organization"
)

// TestOnlyOwnersManageAdmins checks that an admin manages members but not
// other admins: granting, changing, deactivating or removing the admin role
// of someone else needs an owner. An admin may still step down.
func TestOnlyOwnersManageAdmins(t *testing.T) {
	ctx := context.Background()
	api := newOrgAPI(t)
	owner := newHuman(t, api.db, "owner@example.com")
	admin := newHuman(t, api.db, "admin@example.com")
	admin2 := newHuman(t, api.db, "admin2@example.com")
	member := newHuman(t, api.db, "member@example.com")
	member2 := newHuman(t, api.db, "member2@example.com")
	outsider := newHuman(t, api.db, "outsider@example.com")

	org, err := api.svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for who, role := range map[uuid.UUID]string{admin: "admin", admin2: "admin", member: "member", member2: "member"} {
		if _, err := api.svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: who, Role: role}); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
	}
	m := func(id uuid.UUID) string { return "/organizations/acme/members/" + id.String() }
	f := false

	for _, tc := range []struct {
		name   string
		method string
		path   string
		as     uuid.UUID
		body   any
		want   int
	}{
		{"admin promotes member to admin", http.MethodPatch, m(member), admin, map[string]any{"role": "admin"}, 403},
		{"admin demotes another admin", http.MethodPatch, m(admin2), admin, map[string]any{"role": "member"}, 403},
		{"admin deactivates another admin", http.MethodPatch, m(admin2), admin, map[string]any{"active": f}, 403},
		{"admin changes another admin's permissions", http.MethodPatch, m(admin2), admin, map[string]any{"permissions": []string{"x"}}, 403},
		{"admin changes own permissions", http.MethodPatch, m(admin), admin, map[string]any{"permissions": []string{"x"}}, 403},
		{"admin removes another admin", http.MethodDelete, m(admin2), admin, nil, 403},
		{"admin adds an admin directly", http.MethodPost, "/organizations/acme/members", admin, map[string]any{"principal_id": outsider.String(), "role": "admin"}, 403},
		// Members remain an admin's to manage.
		{"admin deactivates a member", http.MethodPatch, m(member2), admin, map[string]any{"active": f}, 200},
		{"admin removes a member", http.MethodDelete, m(member2), admin, nil, 204},
		// Owners manage admins.
		{"owner promotes member to admin", http.MethodPatch, m(member), owner, map[string]any{"role": "admin"}, 200},
		{"owner demotes an admin", http.MethodPatch, m(member), owner, map[string]any{"role": "member"}, 200},
		// An admin may step down.
		{"admin steps down", http.MethodPatch, m(admin2), admin2, map[string]any{"role": "member"}, 200},
		{"owner removes an admin", http.MethodDelete, m(admin), owner, nil, 204},
	} {
		if code, body := api.do(tc.method, tc.path, tc.as, tc.body); code != tc.want {
			t.Errorf("%s: %d, want %d (%s)", tc.name, code, tc.want, body)
		}
	}
}

// TestRoleConditionalWrites checks that an update or removal authorized
// against a role does not apply once the role has changed, so a concurrent
// promotion cannot let an admin demote or remove the new admin.
func TestRoleConditionalWrites(t *testing.T) {
	ctx := context.Background()
	api := newOrgAPI(t)
	owner := newHuman(t, api.db, "owner@example.com")
	target := newHuman(t, api.db, "target@example.com")
	org, err := api.svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m, err := api.svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: target, Role: organization.RoleMember})
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	// An owner promotes the target after an admin's check read "member".
	admin := organization.RoleAdmin
	if _, err := api.svc.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Role: &admin}); err != nil {
		t.Fatalf("promote: %v", err)
	}

	member := organization.RoleMember
	if _, err := api.svc.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Role: &member, IfRole: organization.RoleMember}); !errors.Is(err, organization.ErrMembershipChanged) {
		t.Errorf("stale update: %v, want ErrMembershipChanged", err)
	}
	if err := api.svc.RemoveMemberIfRole(ctx, org.ID, target, organization.RoleMember); !errors.Is(err, organization.ErrMembershipChanged) {
		t.Errorf("stale removal: %v, want ErrMembershipChanged", err)
	}
	got, err := api.svc.GetMembership(ctx, org.ID, target)
	if err != nil || got.Role != organization.RoleAdmin {
		t.Fatalf("membership after stale writes = %+v, %v; want admin", got, err)
	}

	// With the current role, both apply.
	if _, err := api.svc.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Role: &member, IfRole: organization.RoleAdmin}); err != nil {
		t.Errorf("current update: %v", err)
	}
	if err := api.svc.RemoveMemberIfRole(ctx, org.ID, target, organization.RoleMember); err != nil {
		t.Errorf("current removal: %v", err)
	}
}
