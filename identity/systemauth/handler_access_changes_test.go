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
	withTokenProof(t, req)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
		t.Fatalf("token for %s: %d %s", id, w.Code, w.Body)
	}
	return body["access_token"].(string)
}

func getAccessChanges(t *testing.T, s *Server, token, query string) (int, AccessChangesResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, AccessChangesPath+query, nil)
	if token != "" {
		dpopAuth(t, token)(req)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var out AccessChangesResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("access changes body: %v", err)
		}
	}
	return w.Code, out
}

// TestAccessChangesReplayEndpoint verifies who may read the replay
// endpoint, what it returns, and its paging.
func TestAccessChangesReplayEndpoint(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	s := accessChangesServer(t, WithAccessChanges(accesschange.NewSource(db), AllOrganizations))
	base := time.Now().UTC().Add(-time.Hour)
	p, org := uuid.New(), uuid.New()
	for i, c := range []accesschange.Change{
		{PrincipalID: p, OrganizationID: &org, Reason: accesschange.MembershipRemoved},
		{PrincipalID: p, Reason: accesschange.Deactivated},
		{PrincipalID: uuid.New(), Reason: accesschange.SessionsRevoked},
	} {
		// Written directly so each row carries a distinct, known time.
		create := db.AccessChange.Create().SetPrincipalID(c.PrincipalID).SetReason(string(c.Reason)).SetChangedAt(base.Add(time.Duration(i) * time.Minute))
		if c.OrganizationID != nil {
			create.SetOrganizationID(*c.OrganizationID)
		}
		create.SaveX(ctx)
	}
	since := url.QueryEscape(base.Add(-time.Minute).UTC().Format(time.RFC3339Nano))

	if code, _ := getAccessChanges(t, s, "", "?since="+since); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code, _ := getAccessChanges(t, s, "garbage", "?since="+since); code != http.StatusUnauthorized {
		t.Errorf("bad token: %d", code)
	}
	plain := clientToken(t, s, "plain", "plain-secret", "read")
	if code, _ := getAccessChanges(t, s, plain, "?since="+since); code != http.StatusForbidden {
		t.Errorf("token without the scope: %d", code)
	}

	rp := clientToken(t, s, "rp", "rp-secret", AccessChangesScope)
	code, got := getAccessChanges(t, s, rp, "?since="+since)
	if code != http.StatusOK || len(got.Changes) != 3 || got.NextSince != nil {
		t.Fatalf("replay = %d %+v", code, got)
	}
	if got.Changes[0].PrincipalID != p.String() || got.Changes[0].OrganizationID != org.String() || got.Changes[0].Reason != "membership_removed" ||
		got.Changes[1].OrganizationID != "" || got.Changes[1].Reason != "deactivated" {
		t.Errorf("changes = %+v", got.Changes)
	}
	// Only changes after since.
	after := url.QueryEscape(base.Add(30 * time.Second).UTC().Format(time.RFC3339Nano))
	if _, got := getAccessChanges(t, s, rp, "?since="+after); len(got.Changes) != 2 {
		t.Errorf("changes after the first = %d, want 2", len(got.Changes))
	}
	// Paging: a full page carries next_since.
	code, page := getAccessChanges(t, s, rp, "?limit=2&since="+since)
	if code != http.StatusOK || len(page.Changes) != 2 || page.NextSince == nil {
		t.Fatalf("page = %d %+v", code, page)
	}
	if _, rest := getAccessChanges(t, s, rp, "?limit=2&since="+url.QueryEscape(page.NextSince.Format(time.RFC3339Nano))); len(rest.Changes) == 0 || rest.Changes[len(rest.Changes)-1].Reason != "sessions_revoked" {
		t.Errorf("next page = %+v", rest)
	}
	// Bad input.
	for _, q := range []string{"", "?since=yesterday", "?limit=0&since=" + since, "?limit=x&since=" + since} {
		if code, _ := getAccessChanges(t, s, rp, q); code != http.StatusBadRequest {
			t.Errorf("query %q: %d, want 400", q, code)
		}
	}
}

func TestAccessChangesNotConfigured(t *testing.T) {
	s := accessChangesServer(t)
	rp := clientToken(t, s, "rp", "rp-secret", AccessChangesScope)
	if code, _ := getAccessChanges(t, s, rp, "?since=2030-01-01T00:00:00Z"); code != http.StatusNotImplemented {
		t.Errorf("without a lister: %d, want 501", code)
	}
	// A lister without a scope is not served either: the feed is never
	// handed out unfiltered by default.
	s = accessChangesServer(t, WithAccessChanges(accesschange.NewSource(openTestEnt(t)), nil))
	rp = clientToken(t, s, "rp", "rp-secret", AccessChangesScope)
	if code, _ := getAccessChanges(t, s, rp, "?since=2030-01-01T00:00:00Z"); code != http.StatusNotImplemented {
		t.Errorf("without a scope: %d, want 501", code)
	}
}

// TestAccessChangesScopedToClient verifies that a client reads only the
// changes of the organizations its scope names, plus the changes that name
// no organization, so one application does not learn about another's
// members.
func TestAccessChangesScopedToClient(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	mine, theirs := uuid.New(), uuid.New()
	scope := func(_ context.Context, clientID string) ([]uuid.UUID, bool, error) {
		if clientID == "rp" {
			return []uuid.UUID{mine}, false, nil
		}
		return nil, false, nil
	}
	s := accessChangesServer(t, WithAccessChanges(accesschange.NewSource(db), scope))
	base := time.Now().UTC().Add(-time.Hour)
	everywhere := uuid.New()
	for i, c := range []accesschange.Change{
		{PrincipalID: uuid.New(), OrganizationID: &mine, Reason: accesschange.MembershipRemoved},
		{PrincipalID: uuid.New(), OrganizationID: &theirs, Reason: accesschange.MembershipRemoved},
		{PrincipalID: everywhere, Reason: accesschange.Deactivated},
	} {
		create := db.AccessChange.Create().SetPrincipalID(c.PrincipalID).SetReason(string(c.Reason)).SetChangedAt(base.Add(time.Duration(i) * time.Minute))
		if c.OrganizationID != nil {
			create.SetOrganizationID(*c.OrganizationID)
		}
		create.SaveX(ctx)
	}
	since := url.QueryEscape(base.Add(-time.Minute).UTC().Format(time.RFC3339Nano))
	rp := clientToken(t, s, "rp", "rp-secret", AccessChangesScope)
	code, got := getAccessChanges(t, s, rp, "?since="+since)
	if code != http.StatusOK || len(got.Changes) != 2 {
		t.Fatalf("scoped replay = %d %+v", code, got)
	}
	if got.Changes[0].OrganizationID != mine.String() || got.Changes[1].PrincipalID != everywhere.String() {
		t.Errorf("changes = %+v", got.Changes)
	}
	for _, c := range got.Changes {
		if c.OrganizationID == theirs.String() {
			t.Errorf("another application's organization in the feed: %+v", c)
		}
	}
	// Paging follows the unfiltered rows: a page whose rows are all
	// filtered out still leads on.
	code, page := getAccessChanges(t, s, rp, "?limit=2&since="+url.QueryEscape(base.Add(30*time.Second).UTC().Format(time.RFC3339Nano)))
	if code != http.StatusOK || len(page.Changes) != 1 || page.NextSince == nil {
		t.Errorf("filtered page = %d %+v", code, page)
	}
}
