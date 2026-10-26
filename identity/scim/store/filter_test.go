package store_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/scim"
)

// A filter the store cannot evaluate is an invalidFilter error, never a
// filter with the unknown part dropped: an IdP correlating a remote
// identity must not get every user back.
func TestUserFilterFailsClosed(t *testing.T) {
	ctx := scim.WithPlatformScope(context.Background())
	s := newStore(t)
	createUser(t, s, "alice@example.com", "Alice")
	createUser(t, s, "bob@example.com", "Bob")

	for _, f := range []string{
		`title eq "x"`,
		`name.givenName eq "Alice"`,
		`userName eq "nobody@example.com" or title eq "x"`,
		`not (title eq "x")`,
		`emails[type eq "work"].value eq "nobody@example.com"`,
		`emails[type eq "work"]`,
		`userName eq "nobody@example.com" garbage`,
		`userName eq "nobody@example.com" $ or userName pr`,
		`userName gt "a"`,
		`active eq "yes"`,
		`userName eq 42`,
		`meta.created gt "yesterday"`,
		strings.Repeat("(", 100) + `userName pr` + strings.Repeat(")", 100),
	} {
		users, total, err := s.ListUsers(ctx, scim.ListOptions{Filter: f, StartIndex: 1, Count: 10})
		if err == nil {
			t.Errorf("filter %q: %d users, want invalidFilter", f, total)
			continue
		}
		if scimStatus(t, err) != http.StatusBadRequest || len(users) != 0 {
			t.Errorf("filter %q: %v", f, err)
		}
	}

	// Supported constructs still work, and an attribute no user carries
	// matches nobody.
	for f, want := range map[string]int{
		`externalId eq "nope"`: 0,
		`id eq "not-a-uuid"`:   0,
		`userName eq "alice@example.com" or userName eq "nobody@example.com"`: 1,
		`not (userName eq "alice@example.com")`:                               1,
		`(userName pr) and (displayName sw "B")`:                              1,
	} {
		_, total, err := s.ListUsers(ctx, scim.ListOptions{Filter: f, StartIndex: 1, Count: 10})
		if err != nil || total != want {
			t.Errorf("filter %q: total %d, %v; want %d", f, total, err, want)
		}
	}
}

func TestGroupFilterFailsClosed(t *testing.T) {
	ctx := scim.WithPlatformScope(context.Background())
	s := newStore(t)
	if _, err := s.CreateGroup(ctx, &scim.Group{DisplayName: "Alpha"}); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	for _, f := range []string{
		`members.value eq "x"`,
		`displayName eq "Nope" or members.value eq "x"`,
		`displayName gt "A"`,
	} {
		if _, total, err := s.ListGroups(ctx, scim.ListOptions{Filter: f, StartIndex: 1, Count: 10}); err == nil {
			t.Errorf("filter %q: %d groups, want invalidFilter", f, total)
		}
	}
}
