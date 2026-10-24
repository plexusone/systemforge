package systemauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type introspectionFixture struct {
	t *testing.T
	s *Server
}

func newIntrospectionFixture(t *testing.T) *introspectionFixture {
	t.Helper()
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{
			{ID: "resource-server", Secret: "rs-secret", Type: "confidential", Name: "RS",
				GrantTypes: []string{"client_credentials"}, Scopes: []string{"introspect", "read"}},
			{ID: "plain-app", Secret: "plain-secret", Type: "confidential", Name: "App",
				GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"}},
			{ID: "spa", Type: "public", Name: "SPA", RedirectURIs: []string{testRPCB},
				GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{"code"}, Scopes: []string{"read"}},
		},
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return &introspectionFixture{t: t, s: s}
}

func (f *introspectionFixture) token(client, secret, scope string) string {
	f.t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {client}, "client_secret": {secret}, "scope": {scope}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	withTokenProof(f.t, req)
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
		f.t.Fatalf("token for %s: %d %s", client, w.Code, w.Body)
	}
	return body["access_token"].(string)
}

// introspect asks about subject with the given Authorization header.
func (f *introspectionFixture) introspect(subject string, auth func(*http.Request)) (int, map[string]any) {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(url.Values{"token": {subject}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	auth(req)
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		f.t.Fatalf("decode %q: %v", w.Body, err)
	}
	return w.Code, body
}

// TestIntrospectionNeedsAnAuthorizedCaller verifies that only confidential
// clients and holders of an introspection-scoped token may ask about
// someone else's token.
func TestIntrospectionNeedsAnAuthorizedCaller(t *testing.T) {
	f := newIntrospectionFixture(t)
	victim := f.token("plain-app", "plain-secret", "read")
	rsToken := f.token("resource-server", "rs-secret", "introspect")
	lowToken := f.token("plain-app", "plain-secret", "read")

	for name, tc := range map[string]struct {
		auth       func(*http.Request)
		wantStatus int
		wantActive bool
	}{
		"confidential client with Basic":  {func(r *http.Request) { r.SetBasicAuth("resource-server", "rs-secret") }, 200, true},
		"token with the introspect scope": {dpopAuth(t, rsToken), 200, true},
		"bound token sent as Bearer":      {func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+rsToken) }, 401, false},
		"no credentials":                  {func(*http.Request) {}, 401, false},
		"any other access token":          {dpopAuth(t, lowToken), 401, false},
		"garbage bearer":                  {func(r *http.Request) { r.Header.Set("Authorization", "Bearer nonsense") }, 401, false},
		"public client by id":             {func(r *http.Request) { r.SetBasicAuth("spa", "") }, 401, false},
		"unknown client":                  {func(r *http.Request) { r.SetBasicAuth("ghost", "x") }, 401, false},
		"wrong secret":                    {func(r *http.Request) { r.SetBasicAuth("resource-server", "wrong") }, 200, false},
	} {
		status, body := f.introspect(victim, tc.auth)
		if status != tc.wantStatus {
			t.Errorf("%s: status %d, want %d (%v)", name, status, tc.wantStatus, body)
			continue
		}
		if active, _ := body["active"].(bool); active != tc.wantActive {
			t.Errorf("%s: active = %v, want %v (%v)", name, active, tc.wantActive, body)
		}
		if status == http.StatusUnauthorized {
			if _, leaked := body["sub"]; leaked {
				t.Errorf("%s: an unauthorized caller was told about the token: %v", name, body)
			}
		}
	}
}
