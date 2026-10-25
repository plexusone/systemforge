package store_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/store"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// Deleting a user removes its relationships from the graph before the
// deletion commits: platform administration, manager relations on both
// sides and the memberships. If the graph refuses, the user is kept.
func TestDeletingAUserRemovesItsGraphRelationships(t *testing.T) {
	tn := newTenants(t)
	ctx := context.Background()
	memberships, graph := syncrec.New(), syncrec.New()
	tn.s = store.NewEntStore(tn.db, &store.Config{
		BaseURL:     "/scim/v2",
		DefaultRole: "member",
		Memberships: organization.NewService(tn.db, organization.WithAuthzSyncer(memberships)),
		Syncer:      graph,
	})
	alice := tn.create(t, tn.ctxA, "alice@acme.example", "Alice")
	id := uuid.MustParse(alice.ID)
	if _, err := tn.db.Human.Update().Where(human.PrincipalID(id)).SetIsPlatformAdmin(true).Save(ctx); err != nil {
		t.Fatal(err)
	}
	other := tn.create(t, tn.ctxB, "guardian@beta.example", "Guardian")
	child := tn.create(t, tn.ctxB, "child@beta.example", "Child")
	otherID, childID := uuid.MustParse(other.ID), uuid.MustParse(child.ID)
	// Alice is managed by a guardian, and once managed a child (ended).
	if _, err := tn.db.ManagerRelationship.Create().SetManagedPrincipalID(id).SetManagerPrincipalID(otherID).SetRole("guardian").Save(ctx); err != nil {
		t.Fatal(err)
	}
	managing, err := tn.db.ManagerRelationship.Create().SetManagedPrincipalID(childID).SetManagerPrincipalID(id).SetRole("educator").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exists := func() bool {
		t.Helper()
		ok, err := tn.db.Principal.Query().Where(principal.ID(id)).Exist(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	platform := scim.WithPlatformScope(ctx)

	// A user who still manages an account is not deleted.
	if err := tn.s.DeleteUser(platform, alice.ID); scimStatus(t, err) != http.StatusConflict {
		t.Fatalf("DeleteUser of an active manager = %v, want a conflict", err)
	}
	if !exists() {
		t.Fatal("active manager deleted")
	}
	if _, err := tn.db.ManagerRelationship.UpdateOne(managing).SetActive(false).Save(ctx); err != nil {
		t.Fatal(err)
	}

	graph.RemoveErr = errors.New("graph down")
	if err := tn.s.DeleteUser(platform, alice.ID); err == nil {
		t.Fatal("DeleteUser succeeded while the graph refused")
	}
	if !exists() {
		t.Fatal("user deleted although the graph refused")
	}
	graph.RemoveErr = nil
	graph.Reset()

	if err := tn.s.DeleteUser(platform, alice.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	calls := graph.Calls()
	for _, want := range []string{
		fmt.Sprintf("UnregisterPrincipal:%s", id),
		fmt.Sprintf("RemovePrincipalManager:%s:%s:guardian", id, otherID),
		fmt.Sprintf("RemovePrincipalManager:%s:%s:educator", childID, id),
	} {
		if !slices.Contains(calls, want) {
			t.Errorf("missing %s; calls %v", want, calls)
		}
	}
	if exists() {
		t.Error("user not deleted")
	}
}
