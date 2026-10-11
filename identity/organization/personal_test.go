package organization_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/organization"

	_ "github.com/mattn/go-sqlite3"
)

func TestPersonalOrganizationRules(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	svc := organization.NewService(db)
	owner := newHuman(t, db, "owner@example.com")
	other := newHuman(t, db, "other@example.com")
	collab := newHuman(t, db, "collab@example.com")

	personal, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Owner", Slug: "owner", OrgType: organization.OrgTypePersonal, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatalf("Create personal: %v", err)
	}
	if m, err := svc.GetMembership(ctx, personal.ID, owner); err != nil || m.Role != organization.RoleOwner {
		t.Fatalf("owner membership = %+v, %v", m, err)
	}

	for _, role := range []string{organization.RoleMember, organization.RoleAdmin, organization.RoleOwner} {
		_, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: personal.ID, PrincipalID: other, Role: role})
		if !errors.Is(err, organization.ErrPersonalOrganization) {
			t.Errorf("AddMember(%s) = %v, want ErrPersonalOrganization", role, err)
		}
	}

	// A collaborator may be added; it cannot be promoted to a member.
	cm, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: personal.ID, PrincipalID: collab, Role: organization.RoleCollaborator})
	if err != nil {
		t.Fatalf("AddMember(collaborator): %v", err)
	}
	member := organization.RoleMember
	if _, err := svc.UpdateMember(ctx, cm.ID, organization.UpdateMemberInput{Role: &member}); !errors.Is(err, organization.ErrPersonalOrganization) {
		t.Errorf("promoting a collaborator = %v, want ErrPersonalOrganization", err)
	}
	inactive := false
	if _, err := svc.UpdateMember(ctx, cm.ID, organization.UpdateMemberInput{Active: &inactive}); err != nil {
		t.Errorf("deactivating a collaborator: %v", err)
	}
	ownerMembership, err := svc.GetMembership(ctx, personal.ID, owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateMember(ctx, ownerMembership.ID, organization.UpdateMemberInput{Active: &inactive}); !errors.Is(err, organization.ErrPersonalOrganization) {
		t.Errorf("deactivating the owner = %v, want ErrPersonalOrganization", err)
	}

	err = svc.TransferOwnership(ctx, organization.TransferOwnershipInput{OrganizationID: personal.ID, FromPrincipal: owner, ToPrincipal: collab})
	if !errors.Is(err, organization.ErrPersonalOrganization) {
		t.Errorf("TransferOwnership = %v, want ErrPersonalOrganization", err)
	}

	// Team organizations are unaffected.
	team, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: team.ID, PrincipalID: other, Role: organization.RoleMember}); err != nil {
		t.Errorf("AddMember to a team: %v", err)
	}
	if err := svc.TransferOwnership(ctx, organization.TransferOwnershipInput{OrganizationID: team.ID, FromPrincipal: owner, ToPrincipal: other}); err != nil {
		t.Errorf("TransferOwnership of a team: %v", err)
	}
}

// TestRetiredRolesAreRefused checks that editor and viewer, retired as
// organization roles, and unknown roles are refused wherever a membership
// is created or changed.
func TestRetiredRolesAreRefused(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	svc := organization.NewService(db)
	owner := newHuman(t, db, "owner-roles@example.com")
	team, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme-roles", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, role := range []string{"editor", "viewer", "guest", ""} {
		_, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: team.ID, PrincipalID: newHuman(t, db, uuid.NewString()+"@example.com"), Role: role})
		if !errors.Is(err, organization.ErrInvalidRole) {
			t.Errorf("AddMember(%q) = %v, want ErrInvalidRole", role, err)
		}
	}
	for _, role := range []string{"owner", "admin", "member", "collaborator"} {
		if !organization.ValidRole(role) {
			t.Errorf("ValidRole(%q) = false", role)
		}
	}
}
