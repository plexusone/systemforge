package store_test

import (
	"context"
	"testing"

	"github.com/plexusone/systemforge/identity/scim"
)

// Batched membership loads return the same scoped results as the
// per-resource calls: a tenant sees only its own organization.
func TestBatchMembershipsAreScoped(t *testing.T) {
	tn := newTenants(t)
	alice := tn.create(t, tn.ctxA, "alice@acme.example", "Alice")
	bob := tn.create(t, tn.ctxB, "bob@beta.example", "Bob")
	// Alice also joins B.
	if err := tn.s.AddMemberToGroup(scim.WithPlatformScope(context.Background()), tn.orgB.String(), alice.ID); err != nil {
		t.Fatal(err)
	}

	groups, err := tn.s.GetGroupsForUsers(scim.WithPlatformScope(context.Background()), []string{alice.ID, bob.ID, "not-a-uuid"})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups[alice.ID]) != 2 || len(groups[bob.ID]) != 1 {
		t.Errorf("platform groups = %+v", groups)
	}

	groups, err = tn.s.GetGroupsForUsers(tn.ctxA, []string{alice.ID, bob.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups[alice.ID]) != 1 || groups[alice.ID][0].Value != tn.orgA.String() || len(groups[bob.ID]) != 0 {
		t.Errorf("tenant A groups = %+v", groups)
	}

	members, err := tn.s.GetMembersForGroups(tn.ctxA, []string{tn.orgA.String(), tn.orgB.String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(members[tn.orgA.String()]) != 1 || len(members[tn.orgB.String()]) != 0 {
		t.Errorf("tenant A members = %+v", members)
	}
	members, err = tn.s.GetMembersForGroups(scim.WithPlatformScope(context.Background()), []string{tn.orgA.String(), tn.orgB.String()})
	if err != nil {
		t.Fatal(err)
	}
	if len(members[tn.orgA.String()]) != 1 || len(members[tn.orgB.String()]) != 2 {
		t.Errorf("platform members = %+v", members)
	}
}
