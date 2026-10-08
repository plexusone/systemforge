package store_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/store"

	_ "github.com/mattn/go-sqlite3"
)

func newStore(t *testing.T) *store.EntStore {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return store.NewEntStore(db, nil)
}

func scimStatus(t *testing.T, err error) int {
	t.Helper()
	var se *scim.Error
	if !errors.As(err, &se) {
		t.Fatalf("error %v is not a *scim.Error", err)
	}
	return se.Status
}

func boolPtr(b bool) *bool { return &b }

func createUser(t *testing.T, s *store.EntStore, userName, displayName string) *scim.User {
	t.Helper()
	u, err := s.CreateUser(context.Background(), &scim.User{UserName: userName, DisplayName: displayName})
	if err != nil {
		t.Fatalf("CreateUser %s: %v", userName, err)
	}
	return u
}

func TestUserLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	u, err := s.CreateUser(ctx, &scim.User{
		UserName:    "ada@example.com",
		DisplayName: "Ada",
		Photos:      []scim.MultiValue{{Value: "https://example.com/ada.png", Type: "photo", Primary: true}},
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := uuid.Parse(u.ID); err != nil {
		t.Errorf("ID %q is not a UUID", u.ID)
	}
	if u.UserName != "ada@example.com" || u.DisplayName != "Ada" {
		t.Errorf("created user = %+v", u)
	}
	if u.Active == nil || !*u.Active {
		t.Error("active should default to true")
	}
	if len(u.Emails) != 1 || u.Emails[0].Value != "ada@example.com" || !u.Emails[0].Primary {
		t.Errorf("emails = %+v", u.Emails)
	}
	if len(u.Photos) != 1 || u.Photos[0].Value != "https://example.com/ada.png" {
		t.Errorf("photos = %+v", u.Photos)
	}
	if u.Meta == nil || u.Meta.ResourceType != scim.ResourceTypeUser || u.Meta.Location != "/scim/v2/Users/"+u.ID {
		t.Errorf("meta = %+v", u.Meta)
	}

	got, err := s.GetUserByID(ctx, u.ID)
	if err != nil || got.UserName != "ada@example.com" {
		t.Errorf("GetUserByID = %v, %v", got, err)
	}
	got, err = s.GetUserByUserName(ctx, "ada@example.com")
	if err != nil || got.ID != u.ID {
		t.Errorf("GetUserByUserName = %v, %v", got, err)
	}

	updated, err := s.UpdateUser(ctx, u.ID, &scim.User{UserName: "ada.l@example.com", DisplayName: "Ada Lovelace", Active: boolPtr(false)})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if updated.UserName != "ada.l@example.com" || updated.DisplayName != "Ada Lovelace" || updated.Active == nil || *updated.Active {
		t.Errorf("updated user = %+v", updated)
	}

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := s.GetUserByID(ctx, u.ID); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("GetUserByID after delete: %v", err)
	}
}

func TestUserCreateRules(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	u, err := s.CreateUser(ctx, &scim.User{
		Emails: []scim.MultiValue{{Value: "home@example.com", Type: "home"}, {Value: "work@example.com", Type: "work"}},
	})
	if err != nil {
		t.Fatalf("CreateUser from emails: %v", err)
	}
	if u.UserName != "work@example.com" {
		t.Errorf("userName from emails = %q, want the work email", u.UserName)
	}
	if u.DisplayName != "work@example.com" {
		t.Errorf("displayName fallback = %q, want the email", u.DisplayName)
	}

	if _, err := s.CreateUser(ctx, &scim.User{DisplayName: "No Email"}); scimStatus(t, err) != http.StatusBadRequest {
		t.Errorf("create without userName or emails: %v", err)
	}
	if _, err := s.CreateUser(ctx, &scim.User{UserName: "work@example.com"}); scimStatus(t, err) != http.StatusConflict {
		t.Errorf("duplicate userName: %v", err)
	}
	if _, err := s.CreateUser(ctx, &scim.User{UserName: "inactive@example.com", Active: boolPtr(false)}); err != nil {
		t.Errorf("create inactive: %v", err)
	}
}

func TestUserNotFound(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	other := createUser(t, s, "taken@example.com", "Taken")

	for name, err := range map[string]error{
		"get unknown":       func() error { _, err := s.GetUserByID(ctx, uuid.NewString()); return err }(),
		"get invalid":       func() error { _, err := s.GetUserByID(ctx, "not-a-uuid"); return err }(),
		"get by userName":   func() error { _, err := s.GetUserByUserName(ctx, "nobody@example.com"); return err }(),
		"get by externalId": func() error { _, err := s.GetUserByExternalID(ctx, "ext-1"); return err }(),
		"update unknown":    func() error { _, err := s.UpdateUser(ctx, uuid.NewString(), &scim.User{DisplayName: "X"}); return err }(),
		"delete unknown":    s.DeleteUser(ctx, uuid.NewString()),
		"delete invalid":    s.DeleteUser(ctx, "not-a-uuid"),
	} {
		if got := scimStatus(t, err); got != http.StatusNotFound {
			t.Errorf("%s: status %d (%v), want 404", name, got, err)
		}
	}

	u := createUser(t, s, "mover@example.com", "Mover")
	if _, err := s.UpdateUser(ctx, u.ID, &scim.User{UserName: other.UserName}); scimStatus(t, err) != http.StatusConflict {
		t.Errorf("update to a taken userName: %v", err)
	}
}

func TestListUsers(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, n := range []string{"carol", "alice", "bob", "dave"} {
		createUser(t, s, n+"@example.com", "User "+n)
		time.Sleep(2 * time.Millisecond) // distinct created_at for default ordering
	}
	if _, err := s.UpdateUser(ctx, mustGet(t, s, "dave@example.com").ID, &scim.User{Active: boolPtr(false)}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	list := func(opts scim.ListOptions) ([]*scim.User, int) {
		t.Helper()
		if opts.Count == 0 {
			opts.Count = 100
		}
		if opts.StartIndex == 0 {
			opts.StartIndex = 1
		}
		users, total, err := s.ListUsers(ctx, opts)
		if err != nil {
			t.Fatalf("ListUsers %+v: %v", opts, err)
		}
		return users, total
	}
	names := func(us []*scim.User) []string {
		out := make([]string, len(us))
		for i, u := range us {
			out[i] = u.UserName
		}
		return out
	}

	if _, total := list(scim.ListOptions{}); total != 4 {
		t.Errorf("total = %d, want 4", total)
	}
	page, total := list(scim.ListOptions{StartIndex: 2, Count: 2})
	if total != 4 || len(page) != 2 || page[0].UserName != "alice@example.com" || page[1].UserName != "bob@example.com" {
		t.Errorf("page 2 of default (created) order = %v, total %d", names(page), total)
	}
	if us, total := list(scim.ListOptions{Filter: `userName eq "bob@example.com"`}); total != 1 || len(us) != 1 || us[0].UserName != "bob@example.com" {
		t.Errorf("userName eq = %v, total %d", names(us), total)
	}
	if us, total := list(scim.ListOptions{Filter: `displayName co "ali"`}); total != 1 || us[0].UserName != "alice@example.com" {
		t.Errorf("displayName co = %v, total %d", names(us), total)
	}
	if us, total := list(scim.ListOptions{Filter: `userName sw "c"`}); total != 1 || us[0].UserName != "carol@example.com" {
		t.Errorf("userName sw = %v, total %d", names(us), total)
	}
	if us, total := list(scim.ListOptions{Filter: `active eq false`}); total != 1 || us[0].UserName != "dave@example.com" {
		t.Errorf("active eq false = %v, total %d", names(us), total)
	}
	if us, _ := list(scim.ListOptions{Filter: `userName eq "alice@example.com" or userName eq "bob@example.com"`}); len(us) != 2 {
		t.Errorf("or filter = %v, want 2", names(us))
	}
	us, _ := list(scim.ListOptions{SortBy: "userName", SortOrder: "descending"})
	if got := names(us); len(got) != 4 || got[0] != "dave@example.com" || got[3] != "alice@example.com" {
		t.Errorf("sort userName descending = %v", got)
	}
	if _, _, err := s.ListUsers(ctx, scim.ListOptions{Filter: `userName eq`, StartIndex: 1, Count: 10}); scimStatus(t, err) != http.StatusBadRequest {
		t.Errorf("malformed filter: %v", err)
	}
}

func mustGet(t *testing.T, s *store.EntStore, userName string) *scim.User {
	t.Helper()
	u, err := s.GetUserByUserName(context.Background(), userName)
	if err != nil {
		t.Fatalf("GetUserByUserName %s: %v", userName, err)
	}
	return u
}

func TestGroupMembership(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	ada := createUser(t, s, "ada@example.com", "Ada")
	bob := createUser(t, s, "bob@example.com", "Bob")

	g, err := s.CreateGroup(ctx, &scim.Group{DisplayName: "Engineering"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}

	for _, u := range []*scim.User{ada, bob, ada} { // second ada add is a no-op
		if err := s.AddMemberToGroup(ctx, g.ID, u.ID); err != nil {
			t.Fatalf("AddMemberToGroup %s: %v", u.UserName, err)
		}
	}

	members, err := s.GetMembersForGroup(ctx, g.ID)
	if err != nil {
		t.Fatalf("GetMembersForGroup: %v", err)
	}
	byID := map[string]scim.MemberRef{}
	for _, m := range members {
		byID[m.Value] = m
	}
	if len(members) != 2 || byID[ada.ID].Display != "Ada" || byID[bob.ID].Display != "Bob" {
		t.Errorf("members = %+v", members)
	}
	if m := byID[ada.ID]; m.Type != "User" || m.Ref != "/scim/v2/Users/"+ada.ID {
		t.Errorf("member ref = %+v", m)
	}

	groups, err := s.GetGroupsForUser(ctx, ada.ID)
	if err != nil {
		t.Fatalf("GetGroupsForUser: %v", err)
	}
	if len(groups) != 1 || groups[0].Value != g.ID || groups[0].Display != "Engineering" || groups[0].Type != "direct" {
		t.Errorf("groups for ada = %+v", groups)
	}

	if err := s.RemoveMemberFromGroup(ctx, g.ID, ada.ID); err != nil {
		t.Fatalf("RemoveMemberFromGroup: %v", err)
	}
	members, err = s.GetMembersForGroup(ctx, g.ID)
	if err != nil {
		t.Fatalf("GetMembersForGroup after remove: %v", err)
	}
	if len(members) != 1 || members[0].Value != bob.ID {
		t.Errorf("members after remove = %+v", members)
	}
	if groups, err := s.GetGroupsForUser(ctx, ada.ID); err != nil || len(groups) != 0 {
		t.Errorf("groups for ada after remove = %+v, %v", groups, err)
	}

	if err := s.AddMemberToGroup(ctx, "not-a-uuid", ada.ID); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("add to invalid group: %v", err)
	}
}

func TestListGroups(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, n := range []string{"Beta", "Alpha", "Gamma"} {
		if _, err := s.CreateGroup(ctx, &scim.Group{DisplayName: n}); err != nil {
			t.Fatalf("CreateGroup %s: %v", n, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	for _, tc := range []struct {
		name string
		opts scim.ListOptions
		want []string
	}{
		{"default order", scim.ListOptions{}, []string{"Beta", "Alpha", "Gamma"}},
		{"displayName ascending", scim.ListOptions{SortBy: "displayName"}, []string{"Alpha", "Beta", "Gamma"}},
		{"displayName descending", scim.ListOptions{SortBy: "displayName", SortOrder: "descending"}, []string{"Gamma", "Beta", "Alpha"}},
		{"filter", scim.ListOptions{Filter: `displayName eq "Alpha"`}, []string{"Alpha"}},
	} {
		tc.opts.StartIndex, tc.opts.Count = 1, 100
		groups, total, err := s.ListGroups(ctx, tc.opts)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got := make([]string, len(groups))
		for i, g := range groups {
			got[i] = g.DisplayName
		}
		if total != len(tc.want) || len(got) != len(tc.want) {
			t.Errorf("%s: got %v (total %d), want %v", tc.name, got, total, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}
