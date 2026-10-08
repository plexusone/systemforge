package organization_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/organization"

	_ "github.com/mattn/go-sqlite3"
)

func newHuman(t *testing.T, db *ent.Client, email string) uuid.UUID {
	t.Helper()
	p, err := db.Principal.Create().
		SetType(principal.TypeHuman).
		SetIdentifier(email).
		SetDisplayName(email).
		Save(context.Background())
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	return p.ID
}

// TestListExcludesInactiveMemberships verifies that membership listing
// returns only active memberships unless IncludeInactive is passed.
func TestListExcludesInactiveMemberships(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	svc := organization.NewService(db)

	org, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, Plan: organization.PlanFree})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	active := newHuman(t, db, "active@example.com")
	gone := newHuman(t, db, "gone@example.com")
	for _, id := range []uuid.UUID{active, gone} {
		if _, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: id, Role: "member"}); err != nil {
			t.Fatalf("AddMember: %v", err)
		}
	}
	if _, err := db.PrincipalMembership.Update().
		Where(principalmembership.PrincipalIDEQ(gone)).
		SetActive(false).
		Save(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	members, err := svc.ListMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 1 || members[0].PrincipalID != active {
		t.Errorf("ListMembers = %+v, want only the active member", members)
	}
	all, err := svc.ListMembers(ctx, org.ID, organization.IncludeInactive())
	if err != nil {
		t.Fatalf("ListMembers IncludeInactive: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("ListMembers IncludeInactive = %d members, want 2", len(all))
	}

	if ms, err := svc.ListMemberships(ctx, gone); err != nil || len(ms) != 0 {
		t.Errorf("ListMemberships for a deactivated member = %+v, %v; want none", ms, err)
	}
	if ms, err := svc.ListMemberships(ctx, gone, organization.IncludeInactive()); err != nil || len(ms) != 1 {
		t.Errorf("ListMemberships IncludeInactive = %+v, %v; want 1", ms, err)
	}
}

// TestCreateDefaultsTypeAndPlan verifies that an organization created
// without a type or plan takes the schema defaults.
func TestCreateDefaultsTypeAndPlan(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	org, err := organization.NewService(db).Create(ctx, organization.CreateOrganizationInput{Name: "Plain", Slug: "plain"})
	if err != nil {
		t.Fatalf("Create without type or plan: %v", err)
	}
	if org.OrgType != organization.OrgTypeTeam || org.Plan != organization.PlanFree {
		t.Errorf("type %q plan %q, want team and free", org.OrgType, org.Plan)
	}
}
