package store_test

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	entaccesschange "github.com/plexusone/systemforge/identity/ent/accesschange"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/store"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// syncedTenants is tenants whose store changes memberships through an
// organization service that records its authorization-graph calls.
func syncedTenants(t *testing.T) (*tenants, *syncrec.Recorder) {
	t.Helper()
	tn := newTenants(t)
	rec := syncrec.New()
	tn.s = store.NewEntStore(tn.db, &store.Config{
		BaseURL:     "/scim/v2",
		DefaultRole: "member",
		Memberships: organization.NewService(tn.db, organization.WithAuthzSyncer(rec)),
	})
	return tn, rec
}

func accessChanges(t *testing.T, db *ent.Client, principalID string, reason accesschange.Reason) int {
	t.Helper()
	n, err := db.AccessChange.Query().
		Where(entaccesschange.PrincipalIDEQ(uuid.MustParse(principalID)), entaccesschange.ReasonEQ(string(reason))).
		Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// SCIM membership changes carry the same side effects as any other: the
// authorization graph is synced and access changes are recorded, so a
// deprovisioned member's existing tokens stop being honored.
func TestSCIMMembershipChangesHaveSideEffects(t *testing.T) {
	tn, rec := syncedTenants(t)
	alice := tn.create(t, tn.ctxA, "alice@acme.example", "Alice")
	if !slices.Contains(rec.Calls(), fmt.Sprintf("AddOrgMembership:%s:%s:member", alice.ID, tn.orgA)) {
		t.Errorf("create did not sync the membership: %v", rec.Calls())
	}

	if _, err := tn.s.UpdateUser(tn.ctxA, alice.ID, &scim.User{Active: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rec.Calls(), fmt.Sprintf("RemoveOrgMembership:%s:%s:member", alice.ID, tn.orgA)) {
		t.Errorf("suspension did not sync the graph: %v", rec.Calls())
	}
	if accessChanges(t, tn.db, alice.ID, accesschange.MembershipRemoved) == 0 {
		t.Error("suspension recorded no access change")
	}

	// A shared user deleted by a tenant loses that membership the same way.
	bob := tn.create(t, tn.ctxB, "bob@example.com", "Bob")
	tn.create(t, tn.ctxA, "bob@example.com", "Bob")
	before := accessChanges(t, tn.db, bob.ID, accesschange.MembershipRemoved)
	if err := tn.s.DeleteUser(tn.ctxA, bob.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rec.Calls(), fmt.Sprintf("RemoveOrgMembership:%s:%s:member", bob.ID, tn.orgA)) {
		t.Errorf("membership removal did not sync the graph: %v", rec.Calls())
	}
	if accessChanges(t, tn.db, bob.ID, accesschange.MembershipRemoved) <= before {
		t.Error("membership removal recorded no access change")
	}
}

// Deleting a user the tenant owns removes the account, deactivating it
// first so existing tokens stop being honored.
func TestDeletingAnOwnedUserRevokesAccess(t *testing.T) {
	tn, rec := syncedTenants(t)
	alice := tn.create(t, tn.ctxA, "alice@acme.example", "Alice")
	if err := tn.s.DeleteUser(tn.ctxA, alice.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rec.Calls(), fmt.Sprintf("RemoveOrgMembership:%s:%s:member", alice.ID, tn.orgA)) {
		t.Errorf("delete did not sync the graph: %v", rec.Calls())
	}
	if accessChanges(t, tn.db, alice.ID, accesschange.Deactivated) == 0 {
		t.Error("delete recorded no deactivation")
	}
	if n := tn.db.Principal.Query().CountX(context.Background()); n != 0 {
		t.Errorf("%d principals left, want 0", n)
	}
}

// An identity provider cannot lock a customer out of its own organization:
// the organization owner is never suspended or removed through SCIM.
func TestOwnerCannotBeDeprovisioned(t *testing.T) {
	tn, _ := syncedTenants(t)
	owner := tn.create(t, tn.ctxA, "owner@acme.example", "Owner")
	if _, err := tn.db.PrincipalMembership.Update().
		Where(memberIn(owner.ID, tn.orgA)...).
		SetRole(organization.RoleOwner).Save(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := tn.s.UpdateUser(tn.ctxA, owner.ID, &scim.User{Active: boolPtr(false)}); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("owner suspended: %v", err)
	}
	if err := tn.s.RemoveMemberFromGroup(tn.ctxA, tn.orgA.String(), owner.ID); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("owner removed from the group: %v", err)
	}
	if err := tn.s.DeleteUser(tn.ctxA, owner.ID); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("owner deleted: %v", err)
	}
	platform := scim.WithPlatformScope(context.Background())
	if err := tn.s.DeleteUser(platform, owner.ID); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("owner deleted by a platform credential: %v", err)
	}
	if m := tn.membership(t, owner.ID, tn.orgA); m == nil || !m.Active || m.Role != organization.RoleOwner {
		t.Errorf("owner membership changed: %+v", m)
	}
}

// A restored membership gets the default role, not the one it had when it
// was suspended: the identity provider does not manage roles.
func TestRestoredMembershipGetsTheDefaultRole(t *testing.T) {
	tn, _ := syncedTenants(t)
	admin := tn.create(t, tn.ctxA, "admin@acme.example", "Admin")
	if _, err := tn.db.PrincipalMembership.Update().
		Where(memberIn(admin.ID, tn.orgA)...).
		SetRole("admin").Save(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, active := range []bool{false, true} {
		if _, err := tn.s.UpdateUser(tn.ctxA, admin.ID, &scim.User{Active: boolPtr(active)}); err != nil {
			t.Fatal(err)
		}
	}
	if m := tn.membership(t, admin.ID, tn.orgA); m == nil || !m.Active || m.Role != "member" {
		t.Errorf("restored membership = %+v, want active with role member", m)
	}

	// Re-adding through the group restores the same way.
	if _, err := tn.s.UpdateUser(tn.ctxA, admin.ID, &scim.User{Active: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	if err := tn.s.AddMemberToGroup(tn.ctxA, tn.orgA.String(), admin.ID); err != nil {
		t.Fatal(err)
	}
	if m := tn.membership(t, admin.ID, tn.orgA); m == nil || !m.Active || m.Role != "member" {
		t.Errorf("re-added membership = %+v", m)
	}
}

// For a platform credential, active deactivates the account itself.
func TestPlatformActiveDeactivatesTheAccount(t *testing.T) {
	tn, _ := syncedTenants(t)
	ctx := scim.WithPlatformScope(context.Background())
	u := createUser(t, tn.s, "pat@example.com", "Pat")
	if _, err := tn.s.UpdateUser(ctx, u.ID, &scim.User{Active: boolPtr(false)}); err != nil {
		t.Fatal(err)
	}
	if accessChanges(t, tn.db, u.ID, accesschange.Deactivated) != 1 {
		t.Error("deactivation recorded no access change")
	}
	got, err := tn.s.GetUserByID(ctx, u.ID)
	if err != nil || *got.Active {
		t.Errorf("account still active: %+v %v", got, err)
	}
}
