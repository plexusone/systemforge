package organization_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	entaccess "github.com/plexusone/systemforge/identity/ent/accesschange"
	"github.com/plexusone/systemforge/identity/ent/approle"
	"github.com/plexusone/systemforge/identity/ent/resourcegrant"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// Demoting a member to collaborator deletes their application roles and
// removes them from the graph before the change commits; resource grants
// stay.
func TestDemotionToCollaboratorRemovesAppRoles(t *testing.T) {
	testDemotionToCollaborator(t, newDB(t))
}

func TestDemotionToCollaboratorRemovesAppRolesPostgres(t *testing.T) {
	testDemotionToCollaborator(t, newPostgres(t))
}

func testDemotionToCollaborator(t *testing.T, db *ent.Client) {
	t.Helper()
	ctx := context.Background()
	rec := syncrec.New()
	svc := organization.NewService(db, organization.WithAuthzSyncer(rec))
	owner := newHuman(t, db, "owner-"+uuid.NewString()+"@example.com")
	org, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme-" + uuid.NewString()[:8], OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatal(err)
	}
	add := func(active bool) (uuid.UUID, *organization.Membership) {
		t.Helper()
		p := newHuman(t, db, "member-"+uuid.NewString()+"@example.com")
		m, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: p, Role: organization.RoleMember})
		if err != nil {
			t.Fatal(err)
		}
		for _, app := range []string{"notes", "tasks"} {
			if _, err := db.AppRole.Create().SetPrincipalID(p).SetOrganizationID(org.ID).SetApplication(app).SetRole("editor").Save(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.ResourceGrant.Create().SetPrincipalID(p).SetOrganizationID(org.ID).SetResourceType("notes_board").SetResourceID("b1").SetRole("viewer").Save(ctx); err != nil {
			t.Fatal(err)
		}
		if !active {
			no := false
			if _, err := svc.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Active: &no}); err != nil {
				t.Fatal(err)
			}
		}
		return p, m
	}
	count := func(p uuid.UUID) (roles, grants int) {
		t.Helper()
		roles, err := db.AppRole.Query().Where(approle.PrincipalID(p)).Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		grants, err = db.ResourceGrant.Query().Where(resourcegrant.PrincipalID(p)).Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return roles, grants
	}
	collaborator := organization.RoleCollaborator

	// The graph refuses: nothing changes.
	p, m := add(true)
	boom := errors.New("graph down")
	rec.RemoveErr = boom
	if _, err := svc.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Role: &collaborator}); !errors.Is(err, boom) {
		t.Fatalf("refused demotion = %v, want the graph error", err)
	}
	if roles, _ := count(p); roles != 2 {
		t.Errorf("refused demotion left %d application roles, want 2", roles)
	}
	rec.RemoveErr = nil
	rec.Reset()

	// The demotion: roles removed from the graph and deleted, the grant kept,
	// the collaborator relation written after.
	got, err := svc.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Role: &collaborator})
	if err != nil {
		t.Fatalf("demotion: %v", err)
	}
	if got.Role != collaborator {
		t.Errorf("role = %q", got.Role)
	}
	if roles, grants := count(p); roles != 0 || grants != 1 {
		t.Errorf("after demotion: %d application roles, %d grants; want 0 and 1", roles, grants)
	}
	calls := rec.Calls()
	for _, want := range []string{
		fmt.Sprintf("RemoveOrgMembership:%s:%s:member", p, org.ID),
		fmt.Sprintf("RemoveAppRole:%s:%s:notes:editor", p, org.ID),
		fmt.Sprintf("RemoveAppRole:%s:%s:tasks:editor", p, org.ID),
		fmt.Sprintf("AddOrgMembership:%s:%s:collaborator", p, org.ID),
	} {
		if !slices.Contains(calls, want) {
			t.Errorf("missing %s; calls %v", want, calls)
		}
	}
	if slices.Index(calls, fmt.Sprintf("RemoveAppRole:%s:%s:notes:editor", p, org.ID)) >
		slices.Index(calls, fmt.Sprintf("AddOrgMembership:%s:%s:collaborator", p, org.ID)) {
		t.Errorf("collaborator written before the application roles were removed: %v", calls)
	}
	recorded, err := db.AccessChange.Query().
		Where(entaccess.PrincipalID(p), entaccess.Reason(string(accesschange.AppRoleChanged))).
		Exist(ctx)
	if err != nil || !recorded {
		t.Errorf("application role change not recorded: %v, %v", recorded, err)
	}

	// A deactivated member demoted to collaborator loses the rows too.
	q, qm := add(false)
	if _, err := svc.UpdateMember(ctx, qm.ID, organization.UpdateMemberInput{Role: &collaborator}); err != nil {
		t.Fatalf("demotion of a deactivated member: %v", err)
	}
	if roles, grants := count(q); roles != 0 || grants != 1 {
		t.Errorf("deactivated member after demotion: %d application roles, %d grants; want 0 and 1", roles, grants)
	}

	// Demotion and deactivation at once remove the roles from the graph.
	r, rm := add(true)
	rec.Reset()
	no := false
	if _, err := svc.UpdateMember(ctx, rm.ID, organization.UpdateMemberInput{Role: &collaborator, Active: &no}); err != nil {
		t.Fatalf("demotion with deactivation: %v", err)
	}
	if roles, _ := count(r); roles != 0 {
		t.Errorf("demotion with deactivation left %d application roles", roles)
	}
	if calls := rec.Calls(); !slices.Contains(calls, fmt.Sprintf("RemoveAppRole:%s:%s:tasks:editor", r, org.ID)) {
		t.Errorf("application role not removed from the graph; calls %v", calls)
	}
}
