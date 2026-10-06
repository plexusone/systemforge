package systemauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/oauthclient"

	_ "github.com/mattn/go-sqlite3"
)

const testIssuer = "https://auth.example.com"

// --- redirect allowlist ---

func TestRedirectPolicy(t *testing.T) {
	p, err := newRedirectPolicy(testIssuer, &SocialLoginConfig{
		DefaultRedirect:        "/",
		AllowedRedirectOrigins: []string{"https://app.example.com"},
	})
	if err != nil {
		t.Fatalf("newRedirectPolicy: %v", err)
	}

	allowed := []string{
		"/",
		"/oauth/authorize?client_id=a&state=b",
		"https://auth.example.com/welcome",
		"https://app.example.com/dashboard?x=1",
		"https://APP.example.com/",
	}
	for _, raw := range allowed {
		if _, err := p.validate(raw); err != nil {
			t.Errorf("validate(%q) = %v, want allowed", raw, err)
		}
	}

	denied := []string{
		"",
		"https://evil.example.com/",
		"//evil.example.com/",
		"/\\evil.example.com",
		"/\t/evil.example.com",
		"http://app.example.com/", // scheme mismatch
		"https://app.example.com.evil.com/",
		"https://user@app.example.com/",
		"javascript:alert(1)",
		"relative/path",
		"https://app.example.com:8443/",
	}
	for _, raw := range denied {
		if _, err := p.validate(raw); !errors.Is(err, ErrRedirectNotAllowed) {
			t.Errorf("validate(%q) = %v, want ErrRedirectNotAllowed", raw, err)
		}
	}

	if got, err := p.resolve(""); err != nil || got != "/" {
		t.Errorf("resolve(\"\") = %q, %v; want default", got, err)
	}

	if _, err := newRedirectPolicy(testIssuer, &SocialLoginConfig{DefaultRedirect: "https://evil.example.com"}); err == nil {
		t.Error("expected error for disallowed default redirect")
	}
}

// --- account linking (memory directory) ---

func githubLogin(subject, email string, verified bool) ExternalLogin {
	return ExternalLogin{Provider: "github", Subject: subject, Email: email, EmailVerified: verified, Name: "Octo"}
}

func TestResolveExternalLoginMemory(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	t.Run("create then idempotent", func(t *testing.T) {
		dir := NewMemoryPrincipalDirectory()
		p1, err := ResolveExternalLogin(ctx, dir, githubLogin("1", "a@example.com", true), now)
		if err != nil {
			t.Fatalf("first login: %v", err)
		}
		// Email changed upstream: provider subject still wins.
		p2, err := ResolveExternalLogin(ctx, dir, githubLogin("1", "new@example.com", false), now)
		if err != nil {
			t.Fatalf("second login: %v", err)
		}
		if p1.ID != p2.ID {
			t.Fatalf("upsert not idempotent: %s != %s", p1.ID, p2.ID)
		}
		if len(dir.principals) != 1 {
			t.Fatalf("principals = %d, want 1", len(dir.principals))
		}
		if _, ok := dir.LastLogin(p1.ID); !ok {
			t.Error("last login not recorded")
		}
	})

	t.Run("verified email links to verified principal", func(t *testing.T) {
		dir := NewMemoryPrincipalDirectory()
		existing := LoginPrincipal{ID: uuid.New(), Email: "b@example.com", EmailVerified: true, Active: true}
		if err := dir.AddPrincipal(existing); err != nil {
			t.Fatal(err)
		}
		p, err := ResolveExternalLogin(ctx, dir, githubLogin("2", "B@example.com", true), now)
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		if p.ID != existing.ID {
			t.Fatalf("not linked to existing principal")
		}
		if got, err := dir.FindByExternalIdentity(ctx, "github", "2"); err != nil || got.ID != existing.ID {
			t.Fatalf("link not stored: %v", err)
		}
	})

	t.Run("unverified email is not linked", func(t *testing.T) {
		dir := NewMemoryPrincipalDirectory()
		existing := LoginPrincipal{ID: uuid.New(), Email: "c@example.com", EmailVerified: true, Active: true}
		if err := dir.AddPrincipal(existing); err != nil {
			t.Fatal(err)
		}
		_, err := ResolveExternalLogin(ctx, dir, githubLogin("3", "c@example.com", false), now)
		if !errors.Is(err, ErrEmailNotVerified) {
			t.Fatalf("err = %v, want ErrEmailNotVerified", err)
		}
		if _, err := dir.FindByExternalIdentity(ctx, "github", "3"); !errors.Is(err, ErrPrincipalNotFound) {
			t.Fatalf("unverified identity was linked: %v", err)
		}
	})

	t.Run("verified email does not link to unverified principal", func(t *testing.T) {
		dir := NewMemoryPrincipalDirectory()
		if err := dir.AddPrincipal(LoginPrincipal{Email: "d@example.com", Active: true}); err != nil {
			t.Fatal(err)
		}
		_, err := ResolveExternalLogin(ctx, dir, githubLogin("4", "d@example.com", true), now)
		if !errors.Is(err, ErrEmailConflict) {
			t.Fatalf("err = %v, want ErrEmailConflict", err)
		}
	})

	t.Run("unverified email cannot create account", func(t *testing.T) {
		dir := NewMemoryPrincipalDirectory()
		_, err := ResolveExternalLogin(ctx, dir, githubLogin("5", "e@example.com", false), now)
		if !errors.Is(err, ErrEmailNotVerified) {
			t.Fatalf("err = %v, want ErrEmailNotVerified", err)
		}
	})

	t.Run("inactive principal rejected", func(t *testing.T) {
		dir := NewMemoryPrincipalDirectory()
		if err := dir.AddPrincipal(LoginPrincipal{Email: "f@example.com", EmailVerified: true, Active: false}); err != nil {
			t.Fatal(err)
		}
		_, err := ResolveExternalLogin(ctx, dir, githubLogin("6", "f@example.com", true), now)
		if !errors.Is(err, ErrPrincipalInactive) {
			t.Fatalf("err = %v, want ErrPrincipalInactive", err)
		}
	})
}

// --- account linking (Ent directory) ---

func openTestEnt(t *testing.T) *ent.Client {
	t.Helper()
	name := strings.ReplaceAll(t.Name(), "/", "_")
	client := enttest.Open(t, "sqlite3", "file:"+name+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing ent client: %v", err)
		}
	})
	return client
}

func seedHuman(t *testing.T, db *ent.Client, email string, verified bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	p, err := db.Principal.Create().SetType("human").SetIdentifier(email).SetDisplayName(email).Save(ctx)
	if err != nil {
		t.Fatalf("seed principal: %v", err)
	}
	hc := db.Human.Create().SetPrincipalID(p.ID).SetEmail(email)
	if verified {
		hc.SetEmailVerifiedAt(time.Now())
	}
	if _, err := hc.Save(ctx); err != nil {
		t.Fatalf("seed human: %v", err)
	}
	return p.ID
}

func TestResolveExternalLoginEnt(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	t.Run("upsert idempotent", func(t *testing.T) {
		db := openTestEnt(t)
		dir := NewEntPrincipalDirectory(db)
		login := ExternalLogin{Provider: "google", Subject: "g-1", Email: "g@example.com", EmailVerified: true, Name: "G", AvatarURL: "https://img"}
		p1, err := ResolveExternalLogin(ctx, dir, login, now)
		if err != nil {
			t.Fatalf("first login: %v", err)
		}
		p2, err := ResolveExternalLogin(ctx, dir, login, now.Add(time.Minute))
		if err != nil {
			t.Fatalf("second login: %v", err)
		}
		if p1.ID != p2.ID {
			t.Fatal("upsert not idempotent")
		}
		if n := db.Principal.Query().CountX(ctx); n != 1 {
			t.Errorf("principals = %d, want 1", n)
		}
		if n := db.ExternalIdentity.Query().CountX(ctx); n != 1 {
			t.Errorf("external identities = %d, want 1", n)
		}
		if n := db.User.Query().CountX(ctx); n != 0 {
			t.Errorf("legacy users = %d, want 0", n)
		}
		got, err := dir.GetPrincipal(ctx, p1.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Email != "g@example.com" || !got.EmailVerified || got.AvatarURL != "https://img" || !got.Active {
			t.Errorf("unexpected principal: %+v", got)
		}
		h := db.Human.Query().OnlyX(ctx)
		if h.LastLoginAt == nil || !h.LastLoginAt.Equal(now.Add(time.Minute)) {
			t.Errorf("last_login_at = %v", h.LastLoginAt)
		}
	})

	t.Run("verified email links", func(t *testing.T) {
		db := openTestEnt(t)
		dir := NewEntPrincipalDirectory(db)
		existing := seedHuman(t, db, "h@example.com", true)
		p, err := ResolveExternalLogin(ctx, dir, githubLogin("10", "H@example.com", true), now)
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		if p.ID != existing {
			t.Fatal("not linked to existing principal")
		}
	})

	t.Run("unverified email not linked", func(t *testing.T) {
		db := openTestEnt(t)
		dir := NewEntPrincipalDirectory(db)
		seedHuman(t, db, "i@example.com", true)
		_, err := ResolveExternalLogin(ctx, dir, githubLogin("11", "i@example.com", false), now)
		if !errors.Is(err, ErrEmailNotVerified) {
			t.Fatalf("err = %v, want ErrEmailNotVerified", err)
		}
		if n := db.ExternalIdentity.Query().CountX(ctx); n != 0 {
			t.Errorf("external identities = %d, want 0", n)
		}
	})

	t.Run("unverified local principal not linked", func(t *testing.T) {
		db := openTestEnt(t)
		dir := NewEntPrincipalDirectory(db)
		seedHuman(t, db, "j@example.com", false)
		_, err := ResolveExternalLogin(ctx, dir, githubLogin("12", "j@example.com", true), now)
		if !errors.Is(err, ErrEmailConflict) {
			t.Fatalf("err = %v, want ErrEmailConflict", err)
		}
		if n := db.Principal.Query().CountX(ctx); n != 1 {
			t.Errorf("principals = %d, want 1 (create rolled back)", n)
		}
	})

	t.Run("link race reported as existing", func(t *testing.T) {
		db := openTestEnt(t)
		dir := NewEntPrincipalDirectory(db)
		id := seedHuman(t, db, "k@example.com", true)
		login := githubLogin("13", "k@example.com", true)
		if err := dir.LinkExternalIdentity(ctx, id, login); err != nil {
			t.Fatal(err)
		}
		if err := dir.LinkExternalIdentity(ctx, id, login); !errors.Is(err, ErrExternalIdentityExists) {
			t.Fatalf("err = %v, want ErrExternalIdentityExists", err)
		}
		if _, err := dir.CreateFromExternal(ctx, ExternalLogin{Provider: "github", Subject: "13", Email: "other@example.com", EmailVerified: true}); !errors.Is(err, ErrExternalIdentityExists) {
			t.Fatalf("create err = %v, want ErrExternalIdentityExists", err)
		}
	})
}

// --- HTTP flow with a fake GitHub ---

type fakeGitHub struct {
	srv       *httptest.Server
	userID    int64
	email     string
	verified  bool
	exchanges atomic.Int32
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{userID: 4242, email: "octo@example.com", verified: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		f.exchanges.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.PostForm.Get("code") != "upstream-code" || r.PostForm.Get("code_verifier") == "" {
			http.Error(w, `{"error":"bad_verification_code"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		writeTestJSON(t, w, map[string]any{"access_token": "gh-token", "token_type": "bearer"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, map[string]any{"id": f.userID, "login": "octo", "name": "Octo Cat"})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, []map[string]any{{"email": f.email, "primary": true, "verified": f.verified}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encode: %v", err)
	}
}

func (f *fakeGitHub) connector() *oauthclient.Connector {
	c := oauthclient.NewGitHubConnector(oauthclient.ProviderConfig{
		ClientID: "gh-client", ClientSecret: "gh-secret", RedirectURL: testIssuer + "/login/github/callback",
	})
	c.OAuth2.Endpoint = oauth2.Endpoint{
		AuthURL:  f.srv.URL + "/login/oauth/authorize",
		TokenURL: f.srv.URL + "/login/oauth/access_token",
	}
	c.APIURL = f.srv.URL
	c.HTTPClient = f.srv.Client()
	return c
}

func newSocialTestServer(t *testing.T, f *fakeGitHub, dir PrincipalDirectory) *Server {
	t.Helper()
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID:            "spa",
			Type:          "public",
			Name:          "SPA",
			RedirectURIs:  []string{"https://app.example.com/callback"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email"},
		}},
		SocialLogin: &SocialLoginConfig{
			AllowedRedirectOrigins: []string{"https://app.example.com"},
			SkipConsent:            true,
		},
	}, WithSocialConnector(f.connector()), WithPrincipalDirectory(dir))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

func findCookie(t *testing.T, resp *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// startLogin runs GET /login/github and returns the upstream state and the
// state cookie.
func startLogin(t *testing.T, s *Server, returnTo string) (string, *http.Cookie) {
	t.Helper()
	target := "/login/github"
	if returnTo != "" {
		target += "?return_to=" + url.QueryEscape(returnTo)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("start: status %d: %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Errorf("PKCE missing from upstream redirect: %s", loc)
	}
	if q.Get("client_id") != "gh-client" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	sc := findCookie(t, w.Result(), loginStateCookieName)
	if sc == nil {
		t.Fatal("state cookie not set")
	}
	if !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" || sc.Domain != "" {
		t.Errorf("state cookie not hardened: %+v", sc)
	}
	return q.Get("state"), sc
}

func callback(s *Server, state string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/login/github/callback?code=upstream-code&state="+url.QueryEscape(state), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func TestSocialLoginFlow(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s := newSocialTestServer(t, f, dir)

	state, stateCookie := startLogin(t, s, "https://app.example.com/home")
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusFound {
		t.Fatalf("callback: status %d: %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "https://app.example.com/home" {
		t.Errorf("redirect = %q", loc)
	}
	if strings.Contains(w.Header().Get("Location"), "token") {
		t.Error("token leaked into redirect URL")
	}
	sess := findCookie(t, w.Result(), LoginCookieName)
	if sess == nil || sess.Value == "" {
		t.Fatal("__Host-sf_login cookie not set")
	}
	if !sess.Secure || !sess.HttpOnly || sess.SameSite != http.SameSiteLaxMode || sess.Path != "/" || sess.Domain != "" || sess.MaxAge <= 0 {
		t.Errorf("session cookie not hardened: %+v", sess)
	}

	p, err := dir.FindByExternalIdentity(context.Background(), "github", "4242")
	if err != nil {
		t.Fatalf("principal not upserted: %v", err)
	}

	// The session is recognized by the server.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sess)
	got, err := s.CurrentLoginSession(req)
	if err != nil || got.PrincipalID != p.ID || got.Provider != "github" {
		t.Fatalf("CurrentLoginSession = %+v, %v", got, err)
	}

	// Replaying the same state is rejected (single use).
	if w := callback(s, state, stateCookie); w.Code != http.StatusBadRequest {
		t.Errorf("replayed state: status %d, want 400", w.Code)
	}

	// A second login for the same GitHub account reuses the principal.
	state2, stateCookie2 := startLogin(t, s, "")
	w = callback(s, state2, stateCookie2, sess)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/" {
		t.Fatalf("second login: %d %s", w.Code, w.Header().Get("Location"))
	}
	if len(dir.principals) != 1 {
		t.Errorf("principals = %d, want 1", len(dir.principals))
	}
	// The old session token was retired (no fixation / reuse).
	if _, err := s.CurrentLoginSession(req); !errors.Is(err, ErrLoginSessionNotFound) {
		t.Errorf("old session still valid: %v", err)
	}
}

func TestSocialLoginStateMismatch(t *testing.T) {
	f := newFakeGitHub(t)
	s := newSocialTestServer(t, f, NewMemoryPrincipalDirectory())

	state, stateCookie := startLogin(t, s, "")

	// Attacker-supplied state that does not match the browser's cookie.
	otherState, _ := startLogin(t, s, "")
	if w := callback(s, otherState, stateCookie); w.Code != http.StatusBadRequest {
		t.Errorf("mismatched state: status %d, want 400", w.Code)
	}
	// Missing cookie.
	if w := callback(s, state); w.Code != http.StatusBadRequest {
		t.Errorf("missing state cookie: status %d, want 400", w.Code)
	}
	// Unknown state with a matching cookie.
	forged := &http.Cookie{Name: loginStateCookieName, Value: "forged", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
	if w := callback(s, "forged", forged); w.Code != http.StatusBadRequest {
		t.Errorf("unknown state: status %d, want 400", w.Code)
	}
	if n := f.exchanges.Load(); n != 0 {
		t.Errorf("upstream exchange called %d times on invalid state", n)
	}
}

func TestSocialLoginUnverifiedEmail(t *testing.T) {
	f := newFakeGitHub(t)
	f.verified = false
	dir := NewMemoryPrincipalDirectory()
	if err := dir.AddPrincipal(LoginPrincipal{Email: f.email, EmailVerified: true, Active: true}); err != nil {
		t.Fatal(err)
	}
	s := newSocialTestServer(t, f, dir)

	state, stateCookie := startLogin(t, s, "")
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", w.Code, w.Body.String())
	}
	if findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Error("session cookie set for rejected login")
	}
	if _, err := dir.FindByExternalIdentity(context.Background(), "github", "4242"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Errorf("unverified identity linked: %v", err)
	}
}

func TestSocialLoginRejectsOpenRedirect(t *testing.T) {
	f := newFakeGitHub(t)
	s := newSocialTestServer(t, f, NewMemoryPrincipalDirectory())
	for _, target := range []string{"https://evil.example.com/", "//evil.example.com", "/\\evil.example.com"} {
		for _, path := range []string{"/login/github", "/login"} {
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path+"?return_to="+url.QueryEscape(target), nil))
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s return_to=%q: status %d, want 400", path, target, w.Code)
			}
		}
	}
}

func TestSocialLoginUnknownProvider(t *testing.T) {
	f := newFakeGitHub(t)
	s := newSocialTestServer(t, f, NewMemoryPrincipalDirectory())
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login/myspace", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status %d, want 404", w.Code)
	}
}

func TestSocialLoginUpstreamDenied(t *testing.T) {
	f := newFakeGitHub(t)
	s := newSocialTestServer(t, f, NewMemoryPrincipalDirectory())
	_, stateCookie := startLogin(t, s, "")
	req := httptest.NewRequest(http.MethodGet, "/login/github/callback?error=access_denied", nil)
	req.AddCookie(stateCookie)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
}

func TestSocialLoginChooserSingleProvider(t *testing.T) {
	f := newFakeGitHub(t)
	s := newSocialTestServer(t, f, NewMemoryPrincipalDirectory())
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login?return_to=%2Fwelcome", nil))
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/login/github?return_to=%2Fwelcome" {
		t.Errorf("chooser: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestSocialLoginAuthorizeIntegration(t *testing.T) {
	f := newFakeGitHub(t)
	s := newSocialTestServer(t, f, NewMemoryPrincipalDirectory())

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "spa")
	params.Set("redirect_uri", "https://app.example.com/callback")
	params.Set("scope", "openid email")
	params.Set("state", "rp-state-12345")
	params.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	params.Set("code_challenge_method", "S256")
	authorize := "/oauth/authorize?" + params.Encode()

	// Unauthenticated: sent to /login with the authorize URL as return_to.
	w := httptest.NewRecorder()
	unauth := httptest.NewRequest(http.MethodGet, authorize, nil)
	// The header-based default provider must not bypass social login.
	unauth.Header.Set("X-User-ID", uuid.NewString())
	s.ServeHTTP(w, unauth)
	if w.Code != http.StatusFound {
		t.Fatalf("authorize: status %d", w.Code)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != LoginPath || loc.Query().Get("return_to") != authorize {
		t.Fatalf("login redirect = %s", loc)
	}

	// Log in, returning to the authorize URL.
	state, stateCookie := startLogin(t, s, loc.Query().Get("return_to"))
	w = callback(s, state, stateCookie)
	if w.Code != http.StatusFound || w.Header().Get("Location") != authorize {
		t.Fatalf("callback: %d %q", w.Code, w.Header().Get("Location"))
	}
	sess := findCookie(t, w.Result(), LoginCookieName)

	// Authenticated: authorization code issued to the relying party.
	req := httptest.NewRequest(http.MethodGet, authorize, nil)
	req.AddCookie(sess)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("authorize with session: %d %s", w.Code, w.Body.String())
	}
	cb, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if cb.Host != "app.example.com" || cb.Query().Get("code") == "" || cb.Query().Get("state") != "rp-state-12345" {
		t.Fatalf("unexpected client redirect: %s", cb)
	}
}

func TestSocialLoginConfigValidation(t *testing.T) {
	_, err := NewEmbedded(Config{Issuer: testIssuer, SocialLogin: &SocialLoginConfig{}})
	if !errors.Is(err, ErrInvalidSocialLoginConfig) {
		t.Errorf("no providers: err = %v", err)
	}
	_, err = NewEmbedded(Config{Issuer: testIssuer, SocialLogin: &SocialLoginConfig{GitHub: &SocialProviderConfig{ClientID: "x"}}})
	if !errors.Is(err, ErrInvalidSocialLoginConfig) {
		t.Errorf("missing secret: err = %v", err)
	}
	_, err = NewEmbedded(Config{Issuer: testIssuer, SocialLogin: &SocialLoginConfig{
		GitHub:                 &SocialProviderConfig{ClientID: "x", ClientSecret: "y"},
		AllowedRedirectOrigins: []string{"not a url"},
	}})
	if !errors.Is(err, ErrInvalidSocialLoginConfig) {
		t.Errorf("bad origin: err = %v", err)
	}
	s, err := NewEmbedded(Config{Issuer: testIssuer, SocialLogin: &SocialLoginConfig{
		GitHub: &SocialProviderConfig{ClientID: "x", ClientSecret: "y"},
	}})
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	c := s.social.connectors["github"]
	if c.OAuth2.RedirectURL != testIssuer+"/login/github/callback" {
		t.Errorf("default callback = %q", c.OAuth2.RedirectURL)
	}
	if s.config.SocialLogin.SessionLifetime.Duration() != 12*time.Hour {
		t.Errorf("default session lifetime = %v", s.config.SocialLogin.SessionLifetime.Duration())
	}
}

func TestParseConfigSocialLoginEnv(t *testing.T) {
	t.Setenv("TEST_GH_ID", "env-id")
	t.Setenv("TEST_GH_SECRET", "env-secret")
	cfg, err := ParseConfig([]byte(`
issuer: https://auth.example.com
social_login:
  github:
    client_id: ${TEST_GH_ID}
    client_secret: ${TEST_GH_SECRET}
`), FormatYAML)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	gh := cfg.SocialLogin.GitHub
	if gh.ClientID != "env-id" || gh.ClientSecret != "env-secret" {
		t.Errorf("env not expanded: %+v", gh)
	}
	if cfg.SocialLogin.DefaultRedirect != "/" {
		t.Errorf("default redirect = %q", cfg.SocialLogin.DefaultRedirect)
	}
}

func TestMemoryLoginSessionStoreExpiry(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryLoginSessionStore()
	now := time.Now()
	store.now = func() time.Time { return now }
	if err := store.Create(ctx, "tok", LoginSession{PrincipalID: uuid.New(), ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "tok"); err != nil {
		t.Fatalf("get: %v", err)
	}
	for k := range store.sessions {
		if k == "tok" {
			t.Error("raw token stored as key")
		}
	}
	store.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := store.Get(ctx, "tok"); !errors.Is(err, ErrLoginSessionNotFound) {
		t.Fatalf("expired get err = %v", err)
	}
	if err := store.Delete(ctx, "missing"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}
