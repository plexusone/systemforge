package store_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/store"
)

// tenants is a store with two tenant organizations, A and B.
type tenants struct {
	s          *store.EntStore
	db         *ent.Client
	orgA, orgB uuid.UUID
	ctxA, ctxB context.Context
}

func newTenants(t *testing.T) *tenants {
	t.Helper()
	s, db := newStoreWithDB(t)
	ctx := context.Background()
	a, err := db.Organization.Create().SetName("Acme").SetSlug("acme").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := db.Organization.Create().SetName("Beta").SetSlug("beta").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return &tenants{
		s: s, db: db, orgA: a.ID, orgB: b.ID,
		ctxA: scim.WithTenant(ctx, a.ID),
		ctxB: scim.WithTenant(ctx, b.ID),
	}
}

func (tn *tenants) create(t *testing.T, ctx context.Context, email, name string) *scim.User {
	t.Helper()
	u, err := tn.s.CreateUser(ctx, &scim.User{UserName: email, DisplayName: name})
	if err != nil {
		t.Fatalf("CreateUser %s: %v", email, err)
	}
	return u
}

func (tn *tenants) membership(t *testing.T, userID string, org uuid.UUID) *ent.PrincipalMembership {
	t.Helper()
	m, err := tn.db.PrincipalMembership.Query().
		Where(principalmembership.PrincipalIDEQ(uuid.MustParse(userID)), principalmembership.OrganizationIDEQ(org)).
		Only(context.Background())
	if ent.IsNotFound(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestUnscopedRequestsAreRefused(t *testing.T) {
	tn := newTenants(t)
	ctx := context.Background()
	if _, _, err := tn.s.ListUsers(ctx, scim.ListOptions{StartIndex: 1, Count: 10}); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("ListUsers without scope: %v", err)
	}
	if _, err := tn.s.CreateUser(ctx, &scim.User{UserName: "x@example.com"}); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("CreateUser without scope: %v", err)
	}
	if _, _, err := tn.s.ListGroups(ctx, scim.ListOptions{StartIndex: 1, Count: 10}); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("ListGroups without scope: %v", err)
	}
}

func TestTenantSeesOnlyItsMembers(t *testing.T) {
	tn := newTenants(t)
	alice := tn.create(t, tn.ctxA, "alice@acme.example", "Alice")
	bob := tn.create(t, tn.ctxB, "bob@beta.example", "Bob")

	users, total, err := tn.s.ListUsers(tn.ctxA, scim.ListOptions{StartIndex: 1, Count: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(users) != 1 || users[0].ID != alice.ID {
		t.Fatalf("tenant A lists %d users (total %d), want only Alice", len(users), total)
	}
	if _, err := tn.s.GetUserByID(tn.ctxA, bob.ID); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("tenant A read tenant B's user: %v", err)
	}
	if _, err := tn.s.GetUserByUserName(tn.ctxA, "bob@beta.example"); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("tenant A found tenant B's user by userName: %v", err)
	}
	if _, err := tn.s.UpdateUser(tn.ctxA, bob.ID, &scim.User{DisplayName: "Owned"}); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("tenant A updated tenant B's user: %v", err)
	}
	if err := tn.s.DeleteUser(tn.ctxA, bob.ID); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("tenant A deleted tenant B's user: %v", err)
	}
}

// A user provisioned by the tenant and in no other organization is the
// tenant's to change and delete.
func TestTenantManagesUsersItOwns(t *testing.T) {
	tn := newTenants(t)
	alice := tn.create(t, tn.ctxA, "alice@acme.example", "Alice")

	updated, err := tn.s.UpdateUser(tn.ctxA, alice.ID, &scim.User{UserName: "alice.smith@acme.example", DisplayName: "Alice Smith"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.UserName != "alice.smith@acme.example" || updated.DisplayName != "Alice Smith" {
		t.Errorf("owned user not updated: %s %q", updated.UserName, updated.DisplayName)
	}

	if err := tn.s.DeleteUser(tn.ctxA, alice.ID); err != nil {
		t.Fatal(err)
	}
	if exists, err := tn.db.Principal.Query().Where().Exist(context.Background()); err != nil || exists {
		t.Errorf("owned user not deleted: exists=%v err=%v", exists, err)
	}
}

// A user who exists outside the tenant is linked by membership, and the
// tenant cannot change their identity: this is the account-takeover path
// where a tenant rewrites a shared user's login email.
func TestTenantCannotTakeOverSharedUser(t *testing.T) {
	tn := newTenants(t)
	victim := tn.create(t, tn.ctxB, "victim@example.com", "Victim")

	linked := tn.create(t, tn.ctxA, "victim@example.com", "Someone Else")
	if linked.ID != victim.ID {
		t.Fatalf("existing user not linked: got %s, want %s", linked.ID, victim.ID)
	}
	if linked.DisplayName != "Victim" {
		t.Errorf("linking changed the display name to %q", linked.DisplayName)
	}
	if tn.membership(t, victim.ID, tn.orgA) == nil {
		t.Fatal("linked user is not a member of tenant A")
	}

	got, err := tn.s.UpdateUser(tn.ctxA, victim.ID, &scim.User{UserName: "attacker@evil.example", DisplayName: "Attacker"})
	if err != nil {
		t.Fatal(err)
	}
	if got.UserName != "victim@example.com" || got.DisplayName != "Victim" {
		t.Errorf("tenant A changed a shared user's identity: %s %q", got.UserName, got.DisplayName)
	}
	if _, err := tn.s.GetUserByUserName(tn.ctxB, "attacker@evil.example"); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("shared user's email changed as seen by tenant B: %v", err)
	}

	// active=false suspends only tenant A's membership.
	got, err = tn.s.UpdateUser(tn.ctxA, victim.ID, &scim.User{Active: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if *got.Active {
		t.Error("tenant A still reports the user active")
	}
	if m := tn.membership(t, victim.ID, tn.orgA); m == nil || m.Active {
		t.Error("tenant A membership not suspended")
	}
	if inB, err := tn.s.GetUserByID(tn.ctxB, victim.ID); err != nil || !*inB.Active {
		t.Errorf("suspension in A affected B: %+v %v", inB, err)
	}

	// DELETE removes only the membership.
	if err := tn.s.DeleteUser(tn.ctxA, victim.ID); err != nil {
		t.Fatal(err)
	}
	if tn.membership(t, victim.ID, tn.orgA) != nil {
		t.Error("tenant A membership not removed")
	}
	if _, err := tn.s.GetUserByID(tn.ctxB, victim.ID); err != nil {
		t.Errorf("shared user deleted by tenant A: %v", err)
	}
}

// A user the tenant provisioned stops being the tenant's to change once they
// join another organization.
func TestOwnedUserBecomesSharedOnJoiningAnotherOrg(t *testing.T) {
	tn := newTenants(t)
	alice := tn.create(t, tn.ctxA, "alice@acme.example", "Alice")
	if _, err := tn.db.PrincipalMembership.Create().
		SetPrincipalID(uuid.MustParse(alice.ID)).SetOrganizationID(tn.orgB).SetRole("member").
		Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := tn.s.UpdateUser(tn.ctxA, alice.ID, &scim.User{UserName: "other@evil.example"})
	if err != nil {
		t.Fatal(err)
	}
	if got.UserName != "alice@acme.example" {
		t.Errorf("tenant A changed the email of a user who also belongs to B: %s", got.UserName)
	}
}

func TestTenantGroupIsItsOrganization(t *testing.T) {
	tn := newTenants(t)
	alice := tn.create(t, tn.ctxA, "alice@acme.example", "Alice")
	bob := tn.create(t, tn.ctxB, "bob@beta.example", "Bob")
	a, b := tn.orgA.String(), tn.orgB.String()

	groups, total, err := tn.s.ListGroups(tn.ctxA, scim.ListOptions{StartIndex: 1, Count: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(groups) != 1 || groups[0].ID != a {
		t.Fatalf("tenant A lists %d groups, want only its organization", len(groups))
	}
	if _, err := tn.s.GetGroupByID(tn.ctxA, b); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("tenant A read tenant B's group: %v", err)
	}
	if _, err := tn.s.GetGroupByDisplayName(tn.ctxA, "Beta"); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("tenant A found tenant B's group by name: %v", err)
	}
	if _, err := tn.s.GetMembersForGroup(tn.ctxA, b); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("tenant A listed tenant B's members: %v", err)
	}

	if _, err := tn.s.CreateGroup(tn.ctxA, &scim.Group{DisplayName: "New"}); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("tenant created a group: %v", err)
	}
	if _, err := tn.s.UpdateGroup(tn.ctxA, a, &scim.Group{DisplayName: "Renamed"}); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("tenant renamed its organization: %v", err)
	}
	if _, err := tn.s.UpdateGroup(tn.ctxA, a, &scim.Group{DisplayName: "Acme"}); err != nil {
		t.Errorf("update keeping the name refused: %v", err)
	}
	if err := tn.s.DeleteGroup(tn.ctxA, a); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("tenant deleted its organization: %v", err)
	}

	if err := tn.s.AddMemberToGroup(tn.ctxA, b, alice.ID); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("tenant A added a member to tenant B: %v", err)
	}
	if err := tn.s.AddMemberToGroup(tn.ctxA, a, bob.ID); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("tenant A added tenant B's user by ID: %v", err)
	}
	if err := tn.s.RemoveMemberFromGroup(tn.ctxA, b, bob.ID); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("tenant A removed a member of tenant B: %v", err)
	}
	if tn.membership(t, bob.ID, tn.orgB) == nil {
		t.Error("tenant B's membership was removed")
	}

	refs, err := tn.s.GetGroupsForUser(tn.ctxA, alice.ID)
	if err != nil || len(refs) != 1 || refs[0].Value != a {
		t.Errorf("groups for user: %+v %v", refs, err)
	}
}
