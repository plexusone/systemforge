package store_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/store"
	"github.com/plexusone/systemforge/identity/systemauth"
)

func newStoreWithDB(t *testing.T) (*store.EntStore, *ent.Client) {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return store.NewEntStore(db, nil), db
}

// TestUserNameIsNotCaseExact covers RFC 7643 section 4.1.1: userName is not
// case-exact, so lookups, uniqueness, and equality filters ignore case.
func TestUserNameIsNotCaseExact(t *testing.T) {
	ctx := scim.WithPlatformScope(context.Background())
	s := newStore(t)
	u := createUser(t, s, "Ada@Example.com", "Ada")

	if got, err := s.GetUserByUserName(ctx, "ada@example.com"); err != nil || got.ID != u.ID {
		t.Errorf("GetUserByUserName ignoring case = %v, %v", got, err)
	}
	if _, err := s.CreateUser(ctx, &scim.User{UserName: "ADA@example.com"}); scimStatus(t, err) != http.StatusConflict {
		t.Errorf("create with a case variant of a taken userName: %v", err)
	}
	other := createUser(t, s, "grace@example.com", "Grace")
	if _, err := s.UpdateUser(ctx, other.ID, &scim.User{UserName: "ada@EXAMPLE.com"}); scimStatus(t, err) != http.StatusConflict {
		t.Errorf("update to a case variant of a taken userName: %v", err)
	}
	users, total, err := s.ListUsers(ctx, scim.ListOptions{Filter: `userName eq "ADA@EXAMPLE.COM"`, StartIndex: 1, Count: 10})
	if err != nil || total != 1 || users[0].ID != u.ID {
		t.Errorf("userName eq ignoring case = %v (total %d), %v", users, total, err)
	}
}

// TestUsersArePrincipals verifies that SCIM users are human principals, the
// single identity root shared with SystemAuth.
func TestUsersArePrincipals(t *testing.T) {
	ctx := scim.WithPlatformScope(context.Background())
	s, db := newStoreWithDB(t)
	u := createUser(t, s, "lin@example.com", "Lin")

	p, err := db.Principal.Query().Where(principal.IDEQ(uuid.MustParse(u.ID))).WithHuman().Only(ctx)
	if err != nil {
		t.Fatalf("principal for SCIM user: %v", err)
	}
	if p.Type != principal.TypeHuman || p.Edges.Human == nil || p.Edges.Human.Email == nil || *p.Edges.Human.Email != "lin@example.com" || p.DisplayName != "Lin" {
		t.Errorf("principal = %+v, human = %+v", p, p.Edges.Human)
	}

	// The same email arriving through social login must not create a second
	// identity. SCIM-provisioned emails are not marked verified, so social
	// login refuses to link automatically rather than duplicating.
	_, err = systemauth.ResolveExternalLogin(ctx, systemauth.NewEntPrincipalDirectory(db), systemauth.ExternalLogin{
		Provider: "google", Subject: "g-lin", Email: "lin@example.com", EmailVerified: true,
	}, time.Now())
	if !errors.Is(err, systemauth.ErrEmailConflict) {
		t.Errorf("social login for a SCIM-provisioned email error = %v, want ErrEmailConflict", err)
	}
	n, err := db.Principal.Query().Where(principal.TypeEQ(principal.TypeHuman)).Count(ctx)
	if err != nil {
		t.Fatalf("count principals: %v", err)
	}
	if n != 1 {
		t.Errorf("human principals = %d, want 1", n)
	}
}

func TestDeleteUserWithMemberships(t *testing.T) {
	ctx := scim.WithPlatformScope(context.Background())
	s, db := newStoreWithDB(t)
	u := createUser(t, s, "kim@example.com", "Kim")
	g, err := s.CreateGroup(ctx, &scim.Group{DisplayName: "Ops"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.AddMemberToGroup(ctx, g.ID, u.ID); err != nil {
		t.Fatalf("AddMemberToGroup: %v", err)
	}

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser of a group member: %v", err)
	}
	n, err := db.PrincipalMembership.Query().Count(ctx)
	if err != nil {
		t.Fatalf("count memberships: %v", err)
	}
	if n != 0 {
		t.Errorf("memberships after delete = %d, want 0", n)
	}
}

func TestInactiveMembershipsHiddenAndReactivated(t *testing.T) {
	ctx := scim.WithPlatformScope(context.Background())
	s, db := newStoreWithDB(t)
	u := createUser(t, s, "sam@example.com", "Sam")
	g, err := s.CreateGroup(ctx, &scim.Group{DisplayName: "Design"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := s.AddMemberToGroup(ctx, g.ID, u.ID); err != nil {
		t.Fatalf("AddMemberToGroup: %v", err)
	}
	if _, err := db.PrincipalMembership.Update().
		Where(principalmembership.PrincipalIDEQ(uuid.MustParse(u.ID))).
		SetActive(false).
		Save(ctx); err != nil {
		t.Fatalf("deactivate membership: %v", err)
	}

	if members, err := s.GetMembersForGroup(ctx, g.ID); err != nil || len(members) != 0 {
		t.Errorf("members with an inactive membership = %+v, %v", members, err)
	}
	if groups, err := s.GetGroupsForUser(ctx, u.ID); err != nil || len(groups) != 0 {
		t.Errorf("groups with an inactive membership = %+v, %v", groups, err)
	}

	if err := s.AddMemberToGroup(ctx, g.ID, u.ID); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	members, err := s.GetMembersForGroup(ctx, g.ID)
	if err != nil || len(members) != 1 || members[0].Value != u.ID {
		t.Errorf("members after re-add = %+v, %v", members, err)
	}
	if n, err := db.PrincipalMembership.Query().Count(ctx); err != nil || n != 1 {
		t.Errorf("membership rows after re-add = %d, %v; want 1 reactivated row", n, err)
	}
}
