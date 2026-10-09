package systemauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/accesschange"
	entaccesschange "github.com/plexusone/systemforge/identity/ent/accesschange"
)

func accessChangesServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{
			{ID: "rp", Secret: "rp-secret", Type: "confidential", Name: "RP",
				GrantTypes: []string{"client_credentials"}, Scopes: []string{AccessChangesScope, "read"}},
			{ID: "plain", Secret: "plain-secret", Type: "confidential", Name: "Plain",
				GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"}},
		},
	}, opts...)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

func clientToken(t *testing.T, s *Server, id, secret, scope string) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {secret}, "scope": {scope}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
		t.Fatalf("token for %s: %d %s", id, w.Code, w.Body)
	}
	return body["access_token"].(string)
}

func getAccessChanges(s *Server, token, query string) (int, AccessChangesResponse) {
	req := httptest.NewRequest(http.MethodGet, AccessChangesPath+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var out AccessChangesResponse
	if w.Code == http.StatusOK {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}
	return w.Code, out
}

// TestAccessChangesReplayEndpoint verifies who may read the replay
// endpoint, what it returns, and its paging.
func TestAccessChangesReplayEndpoint(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	s := accessChangesServer(t, WithAccessChanges(accesschange.NewSource(db)))
	base := time.Now().UTC().Add(-time.Hour)
	p, org := uuid.New(), uuid.New()
	for i, c := range []accesschange.Change{
		{PrincipalID: p, OrganizationID: &org, Reason: accesschange.MembershipRemoved},
		{PrincipalID: p, Reason: accesschange.Deactivated},
		{PrincipalID: uuid.New(), Reason: accesschange.SessionsRevoked},
	} {
		// Written directly so each row carries a distinct, known time.
		create := db.AccessChange.Create().SetPrincipalID(c.PrincipalID).SetReason(entaccesschange.Reason(c.Reason)).SetChangedAt(base.Add(time.Duration(i) * time.Minute))
		if c.OrganizationID != nil {
			create.SetOrganizationID(*c.OrganizationID)
		}
		create.SaveX(ctx)
	}
	since := url.QueryEscape(base.Add(-time.Minute).UTC().Format(time.RFC3339Nano))

	if code, _ := getAccessChanges(s, "", "?since="+since); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code, _ := getAccessChanges(s, "garbage", "?since="+since); code != http.StatusUnauthorized {
		t.Errorf("bad token: %d", code)
	}
	plain := clientToken(t, s, "plain", "plain-secret", "read")
	if code, _ := getAccessChanges(s, plain, "?since="+since); code != http.StatusForbidden {
		t.Errorf("token without the scope: %d", code)
	}

	rp := clientToken(t, s, "rp", "rp-secret", AccessChangesScope)
	code, got := getAccessChanges(s, rp, "?since="+since)
	if code != http.StatusOK || len(got.Changes) != 3 || got.NextSince != nil {
		t.Fatalf("replay = %d %+v", code, got)
	}
	if got.Changes[0].PrincipalID != p.String() || got.Changes[0].OrganizationID != org.String() || got.Changes[0].Reason != "membership_removed" ||
		got.Changes[1].OrganizationID != "" || got.Changes[1].Reason != "deactivated" {
		t.Errorf("changes = %+v", got.Changes)
	}
	// Only changes after since.
	after := url.QueryEscape(base.Add(30 * time.Second).UTC().Format(time.RFC3339Nano))
	if _, got := getAccessChanges(s, rp, "?since="+after); len(got.Changes) != 2 {
		t.Errorf("changes after the first = %d, want 2", len(got.Changes))
	}
	// Paging: a full page carries next_since.
	code, page := getAccessChanges(s, rp, "?limit=2&since="+since)
	if code != http.StatusOK || len(page.Changes) != 2 || page.NextSince == nil {
		t.Fatalf("page = %d %+v", code, page)
	}
	if _, rest := getAccessChanges(s, rp, "?limit=2&since="+url.QueryEscape(page.NextSince.Format(time.RFC3339Nano))); len(rest.Changes) == 0 || rest.Changes[len(rest.Changes)-1].Reason != "sessions_revoked" {
		t.Errorf("next page = %+v", rest)
	}
	// Bad input.
	for _, q := range []string{"", "?since=yesterday", "?limit=0&since=" + since, "?limit=x&since=" + since} {
		if code, _ := getAccessChanges(s, rp, q); code != http.StatusBadRequest {
			t.Errorf("query %q: %d, want 400", q, code)
		}
	}
}

func TestAccessChangesNotConfigured(t *testing.T) {
	s := accessChangesServer(t)
	rp := clientToken(t, s, "rp", "rp-secret", AccessChangesScope)
	if code, _ := getAccessChanges(s, rp, "?since=2030-01-01T00:00:00Z"); code != http.StatusNotImplemented {
		t.Errorf("without a lister: %d, want 501", code)
	}
}
