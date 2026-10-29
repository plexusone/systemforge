package organization_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/organization"
)

type recordingEmitter struct{ events []audit.Event }

func (r *recordingEmitter) Emit(_ context.Context, ev *audit.Event) error {
	r.events = append(r.events, *ev)
	return nil
}

func TestMembershipAuditEvents(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	rec := &recordingEmitter{}
	svc := organization.NewService(db, organization.WithAuditEmitter(rec))
	owner := newHuman(t, db, "owner@example.com")
	kim := newHuman(t, db, "kim@example.com")
	org, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatal(err)
	}
	m, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: kim, Role: organization.RoleMember})
	if err != nil {
		t.Fatal(err)
	}
	admin := organization.RoleAdmin
	if _, err := svc.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Role: &admin}); err != nil {
		t.Fatal(err)
	}
	if err := svc.TransferOwnership(ctx, organization.TransferOwnershipInput{OrganizationID: org.ID, FromPrincipal: owner, ToPrincipal: kim}); err != nil {
		t.Fatal(err)
	}
	if err := svc.RemoveMember(ctx, org.ID, owner); err != nil {
		t.Fatal(err)
	}

	var actions []string
	for _, ev := range rec.events {
		if ev.EventType != organization.EventMembership || ev.Context.TenantID == nil || *ev.Context.TenantID != org.ID {
			t.Errorf("event: %+v", ev)
		}
		actions = append(actions, ev.Action)
	}
	want := []string{"added", "updated", "ownership_transferred", "removed"}
	if len(actions) != len(want) {
		t.Fatalf("actions = %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Errorf("actions = %v, want %v", actions, want)
		}
	}
	if up := rec.events[1].Details; up["old_role"] != organization.RoleMember || up["role"] != organization.RoleAdmin {
		t.Errorf("role change details: %v", up)
	}
}
