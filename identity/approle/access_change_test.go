package approle_test

import (
	"context"
	"testing"
	"time"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/approle"
)

// TestRoleChangesRecordAccessChanges verifies that changing or removing an
// application role records an access change scoped to the organization,
// and that assigning one (which only adds access) does not.
func TestRoleChangesRecordAccessChanges(t *testing.T) {
	ctx := context.Background()
	var announced []accesschange.Change
	sink := accesschange.SinkFunc(func(c accesschange.Change) { announced = append(announced, c) })
	reg := authz.NewVocabularyRegistry()
	if err := reg.Register(ladderVocab{app: "alpha"}); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, approle.EntitleAll(reg), approle.WithAccessChangeSink(sink))

	if _, err := f.svc.Assign(ctx, f.in(f.member, "alpha", "viewer")); err != nil {
		t.Fatal(err)
	}
	if len(announced) != 0 {
		t.Fatalf("Assign announced %+v", announced)
	}
	if _, err := f.svc.Change(ctx, f.in(f.member, "alpha", "viewer")); err != nil {
		t.Fatal(err)
	}
	if len(announced) != 0 {
		t.Fatalf("a change to the same role announced %+v", announced)
	}
	if _, err := f.svc.Change(ctx, f.in(f.member, "alpha", "admin")); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Remove(ctx, f.org.ID, f.member, "alpha", f.owner); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Assign(ctx, f.in(f.admin, "alpha", "viewer")); err != nil {
		t.Fatal(err)
	}
	if n, err := f.svc.RemoveForMember(ctx, f.org.ID, f.admin); err != nil || n != 1 {
		t.Fatalf("RemoveForMember = %d, %v", n, err)
	}
	if n, err := f.svc.RemoveForMember(ctx, f.org.ID, f.admin); err != nil || n != 0 {
		t.Fatalf("RemoveForMember again = %d, %v", n, err)
	}

	want := []string{f.member.String(), f.member.String(), f.admin.String()}
	if len(announced) != len(want) {
		t.Fatalf("announced %d changes, want %d: %+v", len(announced), len(want), announced)
	}
	for i, c := range announced {
		if c.PrincipalID.String() != want[i] || c.Reason != accesschange.AppRoleChanged || c.OrganizationID == nil || *c.OrganizationID != f.org.ID {
			t.Errorf("announced[%d] = %+v", i, c)
		}
	}
	stored, err := accesschange.Since(ctx, f.db, time.Time{}, 0)
	if err != nil || len(stored) != 3 {
		t.Errorf("stored = %+v, %v; want 3", stored, err)
	}
}
