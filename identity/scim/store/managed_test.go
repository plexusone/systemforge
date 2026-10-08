package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/scim"
)

// addManaged creates a managed principal: a human without an email.
func addManaged(t *testing.T, db *ent.Client) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	if _, err := db.Principal.Create().SetID(id).SetType(entprincipal.TypeHuman).
		SetIdentifier("human:" + id.String()).SetDisplayName("Learner").Save(ctx); err != nil {
		t.Fatalf("principal: %v", err)
	}
	if _, err := db.Human.Create().SetPrincipalID(id).Save(ctx); err != nil {
		t.Fatalf("human: %v", err)
	}
	return id
}

// TestManagedPrincipalsAreNotSCIMUsers verifies that SCIM neither lists,
// reads, changes, deletes, nor groups managed principals.
func TestManagedPrincipalsAreNotSCIMUsers(t *testing.T) {
	ctx := context.Background()
	s, db := newStoreWithDB(t)
	u := createUser(t, s, "kim@example.com", "Kim")
	managed := addManaged(t, db).String()

	users, total, err := s.ListUsers(ctx, scim.ListOptions{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if total != 1 || len(users) != 1 || users[0].ID != u.ID {
		t.Errorf("ListUsers = %d users (total %d), want only %s", len(users), total, u.ID)
	}
	if _, err := s.GetUserByID(ctx, managed); err == nil {
		t.Error("GetUser returned a managed principal")
	}
	if _, err := s.UpdateUser(ctx, managed, &scim.User{UserName: "taken-over@example.com"}); err == nil {
		t.Error("UpdateUser changed a managed principal")
	}
	if err := s.DeleteUser(ctx, managed); err == nil {
		t.Error("DeleteUser deleted a managed principal")
	}
	g, err := s.CreateGroup(ctx, &scim.Group{DisplayName: "Class"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.AddMemberToGroup(ctx, g.ID, managed); err == nil {
		t.Error("AddMemberToGroup added a managed principal")
	}

	// A membership made outside SCIM is not reported as a SCIM member.
	if _, err := db.PrincipalMembership.Create().SetPrincipalID(uuid.MustParse(managed)).
		SetOrganizationID(uuid.MustParse(g.ID)).SetRole("member").Save(ctx); err != nil {
		t.Fatalf("membership: %v", err)
	}
	members, err := s.GetMembersForGroup(ctx, g.ID)
	if err != nil || len(members) != 0 {
		t.Errorf("members = %+v, %v; want none", members, err)
	}

	// The managed principal is untouched.
	if p, err := db.Principal.Get(ctx, uuid.MustParse(managed)); err != nil || p.Identifier != "human:"+managed {
		t.Errorf("managed principal = %+v, %v", p, err)
	}
}
