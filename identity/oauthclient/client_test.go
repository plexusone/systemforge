package oauthclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// fakeProvider serves a token endpoint plus GitHub- and Google-shaped profile
// endpoints.
type fakeProvider struct {
	githubUser   map[string]any
	githubEmails []map[string]any
	emailsStatus int
	googleUser   map[string]any
	gotVerifier  string
}

func (f *fakeProvider) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		f.gotVerifier = r.PostForm.Get("code_verifier")
		if r.PostForm.Get("code") != "good-code" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeJSON(t, w, map[string]any{"access_token": "at-123", "token_type": "bearer", "expires_in": 3600})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-123" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(t, w, f.githubUser)
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		if f.emailsStatus != 0 {
			http.Error(w, "nope", f.emailsStatus)
			return
		}
		writeJSON(t, w, f.githubEmails)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, f.googleUser)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode: %v", err)
	}
}

func testConnector(srv *httptest.Server, provider string) *Connector {
	var c *Connector
	if provider == ProviderGitHub {
		c = NewGitHubConnector(ProviderConfig{ClientID: "id", ClientSecret: "secret"})
		c.APIURL = srv.URL
	} else {
		c = NewGoogleConnector(ProviderConfig{ClientID: "id", ClientSecret: "secret"})
		c.APIURL = srv.URL + "/userinfo"
	}
	c.OAuth2.Endpoint = oauth2.Endpoint{AuthURL: srv.URL + "/authorize", TokenURL: srv.URL + "/token"}
	c.HTTPClient = srv.Client()
	return c
}

func TestConnectorGitHubPublicVerifiedEmail(t *testing.T) {
	f := &fakeProvider{
		githubUser: map[string]any{"id": 42, "login": "octo", "email": "octo@example.com"},
		githubEmails: []map[string]any{
			{"email": "octo@example.com", "primary": true, "verified": true},
		},
	}
	srv := f.server(t)
	c := testConnector(srv, ProviderGitHub)
	ctx := context.Background()

	verifier := oauth2.GenerateVerifier()
	tok, err := c.Exchange(ctx, "good-code", oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if f.gotVerifier != verifier {
		t.Errorf("code_verifier not forwarded: got %q", f.gotVerifier)
	}
	u, err := c.FetchUser(ctx, tok)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if u.ProviderID != "42" || u.Provider != ProviderGitHub || u.Username != "octo" || u.Name != "octo" {
		t.Errorf("unexpected user: %+v", u)
	}
	if u.Email != "octo@example.com" || !u.EmailVerified {
		t.Errorf("email = %q verified=%v, want verified octo@example.com", u.Email, u.EmailVerified)
	}
}

func TestConnectorGitHubPrivateEmailFallback(t *testing.T) {
	f := &fakeProvider{
		githubUser: map[string]any{"id": 7, "login": "priv"},
		githubEmails: []map[string]any{
			{"email": "other@example.com", "primary": false, "verified": false},
			{"email": "main@example.com", "primary": true, "verified": true},
		},
	}
	srv := f.server(t)
	c := testConnector(srv, ProviderGitHub)
	ctx := context.Background()
	tok, err := c.Exchange(ctx, "good-code")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	u, err := c.FetchUser(ctx, tok)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if u.Email != "main@example.com" || !u.EmailVerified {
		t.Errorf("email = %q verified=%v", u.Email, u.EmailVerified)
	}
}

func TestConnectorGitHubUnverifiedPublicEmail(t *testing.T) {
	f := &fakeProvider{
		githubUser:   map[string]any{"id": 8, "login": "u", "email": "pub@example.com"},
		emailsStatus: http.StatusForbidden,
	}
	srv := f.server(t)
	c := testConnector(srv, ProviderGitHub)
	ctx := context.Background()
	tok, err := c.Exchange(ctx, "good-code")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	u, err := c.FetchUser(ctx, tok)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if u.Email != "pub@example.com" || u.EmailVerified {
		t.Errorf("public email without emails scope must be unverified: %+v", u)
	}
}

func TestConnectorGitHubNoEmail(t *testing.T) {
	f := &fakeProvider{githubUser: map[string]any{"id": 9, "login": "u"}, emailsStatus: http.StatusForbidden}
	srv := f.server(t)
	c := testConnector(srv, ProviderGitHub)
	ctx := context.Background()
	tok, err := c.Exchange(ctx, "good-code")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if _, err := c.FetchUser(ctx, tok); err == nil {
		t.Fatal("expected error when no email is available")
	}
}

func TestConnectorGoogle(t *testing.T) {
	f := &fakeProvider{googleUser: map[string]any{
		"sub": "g-1", "email": "g@example.com", "email_verified": true, "name": "G User", "picture": "https://img",
	}}
	srv := f.server(t)
	c := testConnector(srv, ProviderGoogle)
	ctx := context.Background()
	tok, err := c.Exchange(ctx, "good-code")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	u, err := c.FetchUser(ctx, tok)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if u.ProviderID != "g-1" || u.Provider != ProviderGoogle || !u.EmailVerified || u.AvatarURL != "https://img" {
		t.Errorf("unexpected user: %+v", u)
	}
}

func TestConnectorExchangeError(t *testing.T) {
	srv := (&fakeProvider{}).server(t)
	c := testConnector(srv, ProviderGoogle)
	if _, err := c.Exchange(context.Background(), "bad-code"); err == nil {
		t.Fatal("expected exchange error")
	}
}

func TestConnectorUnsupportedProvider(t *testing.T) {
	c := &Connector{Provider: "myspace", OAuth2: &oauth2.Config{}}
	_, err := c.FetchUser(context.Background(), &oauth2.Token{AccessToken: "x"})
	if !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("err = %v, want ErrUnsupportedProvider", err)
	}
}

func TestConnectorAuthCodeURL(t *testing.T) {
	c := NewGitHubConnector(ProviderConfig{ClientID: "cid", ClientSecret: "s", RedirectURL: "https://auth.example.com/cb"})
	raw := c.AuthCodeURL("st", oauth2.S256ChallengeOption(oauth2.GenerateVerifier()))
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	if q.Get("state") != "st" || q.Get("client_id") != "cid" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("unexpected auth URL: %s", raw)
	}
}

func TestMemoryStateStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStateStore()
	if err := s.Put(ctx, "abc", StateData{Provider: ProviderGitHub, RedirectURL: "/x"}, time.Minute); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.Take(ctx, "abc")
	if err != nil || got.Provider != ProviderGitHub || got.RedirectURL != "/x" {
		t.Fatalf("take = %+v, %v", got, err)
	}
	if _, err := s.Take(ctx, "abc"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("second take err = %v, want ErrInvalidState (single use)", err)
	}
	if _, err := s.Take(ctx, "unknown"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("unknown err = %v", err)
	}

	now := time.Now()
	s.now = func() time.Time { return now }
	if err := s.Put(ctx, "exp", StateData{}, time.Second); err != nil {
		t.Fatalf("put: %v", err)
	}
	s.now = func() time.Time { return now.Add(2 * time.Second) }
	if _, err := s.Take(ctx, "exp"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expired err = %v", err)
	}
	if err := s.Put(ctx, "", StateData{}, time.Second); err == nil {
		t.Fatal("expected error for empty state")
	}
}

func TestStateManagerValidate(t *testing.T) {
	m := NewStateManager()

	rec := httptest.NewRecorder()
	m.SetStateCookie(rec, "s1")
	cookie := rec.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly {
		t.Errorf("state cookie not hardened: %+v", cookie)
	}

	req := httptest.NewRequest(http.MethodGet, "/cb?state=s1", nil)
	req.AddCookie(cookie)
	if !m.ValidateState(httptest.NewRecorder(), req, "s1") {
		t.Error("matching state rejected")
	}

	req = httptest.NewRequest(http.MethodGet, "/cb?state=s2", nil)
	req.AddCookie(cookie)
	if m.ValidateState(httptest.NewRecorder(), req, "s2") {
		t.Error("mismatched state accepted")
	}

	req = httptest.NewRequest(http.MethodGet, "/cb", nil)
	req.AddCookie(&http.Cookie{Name: StateCookieName, Value: "", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	if m.ValidateState(httptest.NewRecorder(), req, "") {
		t.Error("empty state accepted")
	}
}
