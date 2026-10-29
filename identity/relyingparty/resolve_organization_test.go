package relyingparty

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveOrganization(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/userinfo/memberships/resolve" || r.Header.Get("Authorization") != "DPoP tok" || r.Header.Get("DPoP") == "" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Query().Get("slug") {
		case "acme":
			writeJSON(w, http.StatusOK, map[string]any{"org": map[string]any{"id": "o1", "slug": "acme", "role": "member", "apps": map[string]any{"alpha": "viewer"}}, "alias": false})
		case "old-acme":
			writeJSON(w, http.StatusOK, map[string]any{"org": map[string]any{"id": "o1", "slug": "acme", "role": "member"}, "alias": true})
		default:
			http.Error(w, "organization not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	c := newTestClient(t, "", srv.Client(), Metadata{UserinfoEndpoint: srv.URL + "/userinfo"})

	m, alias, err := c.ResolveOrganization(t.Context(), "tok", "acme")
	if err != nil || alias || m.OrganizationID != "o1" || m.Applications["alpha"] != "viewer" {
		t.Fatalf("acme = %+v alias %v, %v", m, alias, err)
	}
	m, alias, err = c.ResolveOrganization(t.Context(), "tok", "old-acme")
	if err != nil || !alias || m.OrganizationSlug != "acme" {
		t.Fatalf("old-acme = %+v alias %v, %v", m, alias, err)
	}
	if _, _, err := c.ResolveOrganization(t.Context(), "tok", "other"); !errors.Is(err, ErrOrganizationNotResolved) {
		t.Fatalf("other: %v, want ErrOrganizationNotResolved", err)
	}
	if _, _, err := c.ResolveOrganization(t.Context(), "bad", "acme"); err == nil || errors.Is(err, ErrOrganizationNotResolved) {
		t.Fatalf("rejected token: %v, want a status error", err)
	}
}
