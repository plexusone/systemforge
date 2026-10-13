package connections_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/connections"
)

// TestRolePermissionsWorkWithTheRBACProvider checks the organization roles'
// access to connections through the real role-based provider, not a stand-in.
func TestRolePermissionsWorkWithTheRBACProvider(t *testing.T) {
	ctx := context.Background()
	org, conn := uuid.New(), uuid.New()
	people := map[string]uuid.UUID{
		"owner": uuid.New(), "admin": uuid.New(), "member": uuid.New(),
		"collaborator": uuid.New(), "stranger": uuid.New(),
	}
	roleOf := map[uuid.UUID]string{}
	for role, id := range people {
		if role != "stranger" {
			roleOf[id] = role
		}
	}
	p := rbac.New(
		rbac.WithPermissions(connections.RolePermissions(authz.DefaultRolePermissions)),
		rbac.WithRoleGetter(func(_ context.Context, principal, o uuid.UUID) (string, error) {
			if o != org {
				return "", nil
			}
			return roleOf[principal], nil
		}),
	)
	res := authz.Resource{Type: connections.ResourceType, ID: &conn, OrgID: &org}

	want := map[string][3]bool{ // view, use (edit), manage
		"owner":        {true, true, true},
		"admin":        {true, true, true},
		"member":       {true, false, false},
		"collaborator": {false, false, false},
		"stranger":     {false, false, false},
	}
	for role, id := range people {
		for i, act := range []authz.Action{authz.PermResourceView, authz.PermResourceEdit, authz.PermResourceManage} {
			got, err := p.Can(ctx, authz.NewUserPrincipal(id), act, res)
			if err != nil {
				t.Fatal(err)
			}
			if got != want[role][i] {
				t.Errorf("%s %s = %v, want %v", role, act, got, want[role][i])
			}
		}
	}

	// A connection's creator manages it whatever their role.
	creator := people["member"]
	owned := res
	owned.OwnerID = &creator
	if ok, err := p.Can(ctx, authz.NewUserPrincipal(creator), authz.PermResourceManage, owned); err != nil || !ok {
		t.Errorf("creator manage = %v, %v", ok, err)
	}
}
