package organization_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// Deactivating a membership must take the member's relations out of the
// authorization graph, since a graph-based authorizer (SpiceDB) checks only
// the graph; reactivating writes them back.
func TestDeactivationSyncsTheGraph(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	rec := syncrec.New()
	svc := organization.NewService(db, organization.WithAuthzSyncer(rec))

	org, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	admin := newHuman(t, db, "admin@example.com")
	m, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: admin, Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AppRole.Create().
		SetPrincipalID(admin).SetOrganizationID(org.ID).SetApplication("notes").SetRole("editor").SetAssignedBy(admin).
		Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ResourceGrant.Create().
		SetPrincipalID(admin).SetOrganizationID(org.ID).SetResourceType("notes_board").SetResourceID("b1").SetRole("viewer").SetGrantedBy(admin).
		Save(ctx); err != nil {
		t.Fatal(err)
	}

	no, yes := false, true
	before := len(rec.Calls())
	if _, err := svc.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Active: &no}); err != nil {
		t.Fatal(err)
	}
	removed := rec.Calls()[before:]
	for _, want := range []string{
		fmt.Sprintf("RemoveOrgMembership:%s:%s:admin", admin, org.ID),
		fmt.Sprintf("RemoveAppRole:%s:%s:notes:editor", admin, org.ID),
		fmt.Sprintf("RemoveResourceGrant:%s:%s:notes_board:b1", admin, org.ID),
	} {
		if !slices.Contains(removed, want) {
			t.Errorf("deactivation did not sync %s; calls %v", want, removed)
		}
	}

	// A role change while inactive leaves the graph alone.
	member := "member"
	before = len(rec.Calls())
	if _, err := svc.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Role: &member}); err != nil {
		t.Fatal(err)
	}
	if calls := rec.Calls()[before:]; len(calls) != 0 {
		t.Errorf("role change on an inactive membership synced %v", calls)
	}

	before = len(rec.Calls())
	if _, err := svc.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Active: &yes}); err != nil {
		t.Fatal(err)
	}
	added := rec.Calls()[before:]
	for _, want := range []string{
		fmt.Sprintf("AddOrgMembership:%s:%s:member", admin, org.ID),
		fmt.Sprintf("AddAppRole:%s:%s:notes:editor", admin, org.ID),
		fmt.Sprintf("SetResourceGrant:%s:%s:notes_board:b1:viewer", admin, org.ID),
	} {
		if !slices.Contains(added, want) {
			t.Errorf("reactivation did not sync %s; calls %v", want, added)
		}
	}
}
