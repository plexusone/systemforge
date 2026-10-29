package marketplace

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/rbac"
)

func TestOrgRolePurchaseAuthorizerRoles(t *testing.T) {
	ctx := context.Background()
	p, org := uuid.New(), uuid.New()
	role := "admin"
	orgs := rbac.New(rbac.WithRoleGetter(func(context.Context, uuid.UUID, uuid.UUID) (string, error) { return role, nil }))
	if ok, err := OrgRolePurchaseAuthorizer(orgs).CanPurchase(ctx, p, org); err != nil || !ok {
		t.Errorf("admin default = %v, %v", ok, err)
	}
	if ok, err := OrgRolePurchaseAuthorizer(orgs, "owner").CanPurchase(ctx, p, org); err != nil || ok {
		t.Errorf("admin with owner-only = %v, %v", ok, err)
	}
	var _ authz.OrgAuthorizer = orgs
}
