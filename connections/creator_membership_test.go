package connections_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	cf "github.com/plexusone/connectforge"
	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/connections"
)

// A connection's creator manages it only while a member of the owning
// organization; once removed, they keep no access and cannot share it back
// to themselves.
func TestCreatorRightsEndWithMembership(t *testing.T) {
	ctx := context.Background()
	org, conn, creator, other := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	roleOf := map[uuid.UUID]string{creator: "member", other: "member"}
	p := rbac.New(
		rbac.WithPermissions(connections.RolePermissions(authz.DefaultRolePermissions)),
		rbac.WithRoleGetter(func(_ context.Context, principal, o uuid.UUID) (string, error) {
			if o != org {
				return "", nil
			}
			return roleOf[principal], nil
		}),
	)
	c := open(t, connections.Options{Authorizer: p})
	stored := cf.Connection{
		ID: conn.String(), Owner: connections.OwnerFor(org), Revision: 1,
		CreatedBy: cf.Principal{Kind: cf.PrincipalUser, ID: creator.String()},
	}
	as := func(id uuid.UUID) cf.Principal { return cf.Principal{Kind: cf.PrincipalUser, ID: id.String()} }

	if err := c.Authorizer.Allowed(ctx, as(creator), cf.ActionManage, stored); err != nil {
		t.Errorf("member creator cannot manage: %v", err)
	}
	if err := c.Authorizer.Allowed(ctx, as(other), cf.ActionManage, stored); !errors.Is(err, cf.ErrDenied) {
		t.Errorf("another member manages the creator's connection: %v", err)
	}

	delete(roleOf, creator) // removed from the organization
	for _, act := range []cf.Action{cf.ActionView, cf.ActionUse, cf.ActionManage, cf.ActionShare, cf.ActionDisconnect} {
		if err := c.Authorizer.Allowed(ctx, as(creator), act, stored); !errors.Is(err, cf.ErrDenied) {
			t.Errorf("removed creator allowed %s: %v", act, err)
		}
	}
}
