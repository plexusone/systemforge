package systemauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/plexusone/systemforge/identity/approle"
	entorg "github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/organization"
)

func resolveMembership(t *testing.T, s *Server, token, slug string) (int, ResolveMembershipResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, ResolveMembershipPath+"?slug="+url.QueryEscape(slug), nil)
	dpopAuth(t, token)(req)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var out ResolveMembershipResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("resolve body: %v", err)
		}
	}
	if cc := w.Header().Get("Cache-Control"); w.Code != http.StatusUnauthorized && cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	return w.Code, out
}

func TestResolveMembership(t *testing.T) {
	f := newOrgsFixture(t)
	ctx := context.Background()
	team := f.join(t, "acme", organization.RoleOwner, 0)
	if _, err := f.roles.Assign(ctx, approle.AssignInput{OrganizationID: team.ID, PrincipalID: f.principal, Application: "notes", Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	// An organization the principal does not belong to.
	if _, err := f.db.Organization.Create().SetName("Other").SetSlug("other-org").SetOrgType(entorg.OrgTypeTeam).Save(ctx); err != nil {
		t.Fatal(err)
	}
	at := f.tokens(t, "openid")["access_token"].(string)

	code, got := resolveMembership(t, f.s, at, "acme")
	if code != http.StatusOK || got.Alias || got.Org.ID != team.ID.String() || got.Org.Slug != "acme" ||
		got.Org.Role != organization.RoleOwner || got.Org.Apps["notes"] == "" || got.Org.Type != "team" {
		t.Fatalf("acme: %d %+v", code, got)
	}

	// After a rename the old slug still resolves, as an alias.
	if err := organization.NewService(f.db).Rename(ctx, team.ID, "acme-inc", f.principal); err != nil {
		t.Fatal(err)
	}
	code, got = resolveMembership(t, f.s, at, "acme")
	if code != http.StatusOK || !got.Alias || got.Org.ID != team.ID.String() || got.Org.Slug != "acme-inc" {
		t.Fatalf("old slug: %d %+v", code, got)
	}
	if code, got = resolveMembership(t, f.s, at, "acme-inc"); code != http.StatusOK || got.Alias {
		t.Fatalf("new slug: %d %+v", code, got)
	}

	// Not a member and unknown answer alike.
	for _, slug := range []string{"other-org", "no-such-org"} {
		if code, _ := resolveMembership(t, f.s, at, slug); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", slug, code)
		}
	}
	if code, _ := resolveMembership(t, f.s, at, ""); code != http.StatusBadRequest {
		t.Errorf("no slug: %d, want 400", code)
	}
	if code, _ := resolveMembership(t, f.s, "not-a-token", "acme"); code != http.StatusUnauthorized {
		t.Errorf("bad token: %d, want 401", code)
	}
}
