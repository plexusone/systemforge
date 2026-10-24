package authz_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/rbac"
)

// A route registered with no actions must not be open to every caller.
func TestRequireActionsPanicsWithoutActions(t *testing.T) {
	mw := authz.NewMiddleware(rbac.New())
	for name, register := range map[string]func(){
		"all": func() { mw.RequireAllActions("document") },
		"any": func() { mw.RequireAnyAction("document") },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("registering without actions did not panic")
				}
			}()
			register()
		})
	}
}

// CanAll over no actions is denied, even for a caller with every role
// permission.
func TestRBACCanAllDeniesEmptyActions(t *testing.T) {
	org := uuid.New()
	p := rbac.New(
		rbac.WithPermissions(authz.RolePermissions{"admin": {"document.read"}}),
		rbac.WithRoleGetter(func(context.Context, uuid.UUID, uuid.UUID) (string, error) { return "admin", nil }),
	)
	ok, err := p.CanAll(context.Background(), authz.NewUserPrincipal(uuid.New()), nil, authz.NewResource("document").WithOrg(org))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("CanAll with no actions allowed the caller")
	}
}
