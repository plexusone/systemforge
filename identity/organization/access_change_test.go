package organization_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/organization"
)

type changeLog struct {
	mu  sync.Mutex
	got []accesschange.Change
}

func (l *changeLog) AccessChange(c accesschange.Change) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.got = append(l.got, c)
}

func (l *changeLog) reset() []accesschange.Change {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.got
	l.got = nil
	return out
}

// TestMembershipChangesRecordAccessChanges verifies that removal, role
// change, deactivation and ownership transfer each record an access change
// in their transaction and announce it after commit (ADR-010).
func TestMembershipChangesRecordAccessChanges(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	sink := &changeLog{}
	svc := organization.NewService(db, organization.WithAccessChangeSink(sink))
	owner := newHuman(t, db, "owner@example.com")
	kim := newHuman(t, db, "kim@example.com")
	lee := newHuman(t, db, "lee@example.com")
	org, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatal(err)
	}
	var kimMembership *organization.Membership
	for _, p := range []uuid.UUID{kim, lee} {
		m, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: p, Role: organization.RoleMember})
		if err != nil {
			t.Fatal(err)
		}
		if p == kim {
			kimMembership = m
		}
	}
	if got := sink.reset(); len(got) != 0 {
		t.Fatalf("adding members announced %+v; only reductions are changes", got)
	}
	stored := func() []accesschange.Change {
		t.Helper()
		got, err := accesschange.Since(ctx, db, time.Time{}, 0)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	check := func(name string, want ...accesschange.Change) {
		t.Helper()
		announced := sink.reset()
		if len(announced) != len(want) {
			t.Fatalf("%s: announced %+v, want %d changes", name, announced, len(want))
		}
		for i, w := range want {
			a := announced[i]
			if a.PrincipalID != w.PrincipalID || a.Reason != w.Reason || a.OrganizationID == nil || *a.OrganizationID != org.ID || a.ChangedAt.IsZero() {
				t.Errorf("%s: announced[%d] = %+v, want %+v in %s", name, i, a, w, org.ID)
			}
		}
	}

	// A role change.
	admin := organization.RoleAdmin
	if _, err := svc.UpdateMember(ctx, kimMembership.ID, organization.UpdateMemberInput{Role: &admin}); err != nil {
		t.Fatal(err)
	}
	check("role change", accesschange.Change{PrincipalID: kim, Reason: accesschange.OrgRoleChanged})
	// Setting the role it already has changes nothing.
	if _, err := svc.UpdateMember(ctx, kimMembership.ID, organization.UpdateMemberInput{Role: &admin}); err != nil {
		t.Fatal(err)
	}
	check("same role")
	// Deactivating the membership.
	off := false
	if _, err := svc.UpdateMember(ctx, kimMembership.ID, organization.UpdateMemberInput{Active: &off}); err != nil {
		t.Fatal(err)
	}
	check("deactivation", accesschange.Change{PrincipalID: kim, Reason: accesschange.MembershipRemoved})
	// Removal.
	if err := svc.RemoveMember(ctx, org.ID, lee); err != nil {
		t.Fatal(err)
	}
	check("removal", accesschange.Change{PrincipalID: lee, Reason: accesschange.MembershipRemoved})
	// Ownership transfer changes both principals.
	on := true
	if _, err := svc.UpdateMember(ctx, kimMembership.ID, organization.UpdateMemberInput{Active: &on}); err != nil {
		t.Fatal(err)
	}
	sink.reset()
	if err := svc.TransferOwnership(ctx, organization.TransferOwnershipInput{OrganizationID: org.ID, FromPrincipal: owner, ToPrincipal: kim}); err != nil {
		t.Fatal(err)
	}
	check("transfer",
		accesschange.Change{PrincipalID: owner, Reason: accesschange.OrgRoleChanged},
		accesschange.Change{PrincipalID: kim, Reason: accesschange.OrgRoleChanged})

	// Every announced change was also stored: 5 reductions in all.
	if rows := stored(); len(rows) != 5 {
		t.Errorf("stored changes = %d, want 5: %+v", len(rows), rows)
	}
}
