package organization_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/identity/organization"
)

// A deleted organization is soft-deleted (inactive). Under the RBAC
// authorizer, which reads roles from memberships, it must grant its former
// members nothing, stop resolving by slug, and take no new members, as
// unregistering it does in the relationship graph.
func TestDeletedOrganizationIsInert(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	svc := organization.NewService(db)
	owner := newHuman(t, db, "owner@example.com")
	org, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatal(err)
	}
	admin := newHuman(t, db, "admin@example.com")
	if _, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: admin, Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	authorizer := rbac.New(rbac.WithRoleGetter(organization.MembershipRoleGetter(svc)))
	orgRes := authz.NewResourceWithID(authz.ResourceTypeOrganization, org.ID)
	if ok, err := authorizer.Can(ctx, authz.NewUserPrincipal(admin), authz.PermOrgInviteMember, orgRes); err != nil || !ok {
		t.Fatalf("admin before delete: %v, %v", ok, err)
	}

	if err := svc.Delete(ctx, org.ID); err != nil {
		t.Fatal(err)
	}

	for _, who := range []uuid.UUID{owner, admin} {
		ok, err := authorizer.Can(ctx, authz.NewUserPrincipal(who), authz.PermOrgView, orgRes)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("%s may still view the deleted organization", who)
		}
	}
	if _, _, err := svc.ResolveSlug(ctx, "acme"); !errors.Is(err, organization.ErrOrganizationNotFound) {
		t.Errorf("ResolveSlug of a deleted organization: err = %v, want ErrOrganizationNotFound", err)
	}
	other := newHuman(t, db, "other@example.com")
	if _, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: other, Role: "member"}); !errors.Is(err, organization.ErrOrganizationDeleted) {
		t.Errorf("AddMember to a deleted organization: err = %v, want ErrOrganizationDeleted", err)
	}
	if err := organization.RequireMembersAllowed(ctx, db, org.ID, organization.RoleCollaborator); !errors.Is(err, organization.ErrOrganizationDeleted) {
		t.Errorf("RequireMembersAllowed for a collaborator: err = %v, want ErrOrganizationDeleted", err)
	}
}
