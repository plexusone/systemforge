package appauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/appauth"
	"github.com/plexusone/systemforge/identity/publicclient"
	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// headerSession is a SystemAuth session provider for tests: the signed-in
// user is the X-Test-User header.
type headerSession struct{}

func (headerSession) GetAuthenticatedUser(r *http.Request) string { return r.Header.Get("X-Test-User") }
func (headerSession) RedirectToLogin(string) string               { return "/login" }
func (headerSession) HasConsent(context.Context, string, string, []string) bool {
	return true
}
func (headerSession) RedirectToConsent(string) string { return "/consent" }
func (headerSession) SaveConsent(context.Context, string, string, []string) error {
	return nil
}
func (headerSession) GetUserClaims(_ context.Context, userID string, _ []string) map[string]any {
	return map[string]any{"sub": userID, "email": "dev@example.com", "email_verified": true, "name": "Dev"}
}

const clientSecret = "app-secret-for-tests-only" //nolint:gosec // G101: a test fixture

// env is an embedded SystemAuth that requires DPoP nonces, with a
// confidential client "app" for the application and a public client "cli",
// and an application served by an appauth.Authenticator.
type env struct {
	t          *testing.T
	issuer     string
	user       string
	app        *httptest.Server
	mux        *http.ServeMux
	cfg        appauth.Config
	principals *relyingparty.MemoryPrincipalStore
	sessions   *relyingparty.MemorySessionStore
	states     *relyingparty.MemoryLoginStateStore
	auth       *appauth.Authenticator
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, mux: http.NewServeMux()}
	var sa *systemauth.Server
	saSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sa.ServeHTTP(w, r) }))
	t.Cleanup(saSrv.Close)
	e.app = httptest.NewServer(e.mux)
	t.Cleanup(e.app.Close)
	var err error
	sa, err = systemauth.NewEmbedded(systemauth.Config{
		Issuer: saSrv.URL,
		Clients: []systemauth.ClientConfig{
			{
				ID: "app", Secret: clientSecret, Type: "confidential", Name: "App",
				RedirectURIs:  []string{e.app.URL + "/bff/auth/callback"},
				GrantTypes:    []string{"authorization_code", "refresh_token"},
				ResponseTypes: []string{"code"},
				Scopes:        []string{"openid", "profile", "email", "offline_access"},
			},
			{
				ID: "cli", Type: "public", Name: "CLI",
				RedirectURIs:  []string{publicclient.RegisteredRedirectURI},
				GrantTypes:    []string{"authorization_code", "refresh_token"},
				ResponseTypes: []string{"code"},
				Scopes:        []string{"openid", "profile", "email", "offline_access"},
			},
		},
		Features: systemauth.FeatureConfig{RequirePKCE: true, EnableJWTAccessTokens: true},
		DPoP:     systemauth.DPoPConfig{RequireNonce: true, NonceSecret: strings.Repeat("s", 32)},
	}, systemauth.WithSessionProvider(headerSession{}))
	if err != nil {
		t.Fatal(err)
	}
	human := &systemauth.HumanPrincipal{Email: "dev@example.com", EmailVerified: true, Active: true}
	if err := sa.Storage().CreateHuman(t.Context(), human); err != nil {
		t.Fatal(err)
	}
	e.issuer, e.user = saSrv.URL, human.ID.String()
	e.cfg = appauth.Config{
		Issuer: saSrv.URL, ClientID: "app", ClientSecret: clientSecret,
		PublicURL: e.app.URL, AcceptedClientIDs: []string{"cli"}, DPoPKey: newKeyPEM(t),
	}
	e.principals = relyingparty.NewMemoryPrincipalStore()
	e.sessions = relyingparty.NewMemorySessionStore()
	e.states = relyingparty.NewMemoryLoginStateStore()
	e.auth = e.newAuth(t)
	e.mux.Handle("/bff/", e.auth.Handler())
	e.mux.Handle("/api/", e.auth.Middleware(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := requestprincipal.FromContext(r.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusInternalServerError)
			return
		}
		if _, err := fmt.Fprintf(w, "%s %s", p.Protocol, p.Subject); err != nil {
			t.Error(err)
		}
	})))
	return e
}

func (e *env) newAuth(t *testing.T) *appauth.Authenticator {
	t.Helper()
	a, err := appauth.New(t.Context(), e.cfg, appauth.Options{
		Principals: e.principals, Sessions: e.sessions, LoginStates: e.states,
		Memberships: relyingparty.NoMemberships,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func newKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// signIn runs the browser sign-in through the application's BFF and
// SystemAuth, and returns the session cookie.
func (e *env) signIn() *http.Cookie {
	e.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		e.t.Fatal(err)
	}
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	next := e.app.URL + "/bff/auth/login"
	for range 4 {
		req, err := http.NewRequestWithContext(e.t.Context(), http.MethodGet, next, nil)
		if err != nil {
			e.t.Fatal(err)
		}
		if strings.HasPrefix(next, e.issuer) {
			req.Header.Set("X-Test-User", e.user)
		}
		resp, err := browser.Do(req)
		if err != nil {
			e.t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			e.t.Fatal(err)
		}
		loc := resp.Header.Get("Location")
		if resp.StatusCode/100 != 3 || loc == "" {
			e.t.Fatalf("sign-in at %s: %d", next, resp.StatusCode)
		}
		u, err := url.Parse(next)
		if err != nil {
			e.t.Fatal(err)
		}
		target, err := u.Parse(loc)
		if err != nil {
			e.t.Fatal(err)
		}
		if strings.HasPrefix(next, e.app.URL+"/bff/auth/callback") {
			appURL, err := url.Parse(e.app.URL)
			if err != nil {
				e.t.Fatal(err)
			}
			for _, c := range jar.Cookies(appURL) {
				if strings.HasSuffix(c.Name, "sf_rp_session") {
					return c
				}
			}
			e.t.Fatalf("no session cookie after the callback")
		}
		next = target.String()
	}
	e.t.Fatal("sign-in did not finish")
	return nil
}

func (e *env) request(method, path string, decorate func(*http.Request)) *http.Request {
	req := httptest.NewRequest(method, e.app.URL+path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	if decorate != nil {
		decorate(req)
	}
	return req
}

func withCookie(c *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(c) }
}

func TestSessionRequests(t *testing.T) {
	e := newEnv(t)
	cookie := e.signIn()

	p, err := e.auth.Authenticate(e.request(http.MethodGet, "/api/me", withCookie(cookie)))
	if err != nil || p.Protocol != requestprincipal.ProtocolSession || p.Subject != e.user {
		t.Fatalf("session: %+v %v", p, err)
	}
	if _, ok := p.Native.(*relyingparty.AuthenticatedPrincipal); !ok {
		t.Errorf("native: %T", p.Native)
	}

	// A same-origin JSON write passes; a cross-origin one is forbidden.
	same := e.request(http.MethodPost, "/api/things", withCookie(cookie))
	same.Header.Set("Origin", e.app.URL)
	if _, err := e.auth.Authenticate(same); err != nil {
		t.Fatalf("same-origin write: %v", err)
	}
	cross := e.request(http.MethodPost, "/api/things", withCookie(cookie))
	cross.Header.Set("Origin", "https://evil.example")
	_, err = e.auth.Authenticate(cross)
	if !errors.Is(err, appauth.ErrForbidden) || errors.Is(err, appauth.ErrUnauthenticated) {
		t.Fatalf("cross-origin write: %v", err)
	}
	if ch := appauth.Challenges(err); len(ch) != 0 {
		t.Errorf("cross-origin challenges: %v", ch)
	}

	// The session's token can be forwarded; a request with its own
	// credential has none to forward.
	tok, err := e.auth.SessionToken(e.request(http.MethodGet, "/api/me", withCookie(cookie)))
	if err != nil || tok == "" {
		t.Fatalf("session token: %q %v", tok, err)
	}
	withAuth := e.request(http.MethodGet, "/api/me", func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Authorization", "DPoP x")
	})
	if _, err := e.auth.SessionToken(withAuth); !errors.Is(err, appauth.ErrNoSessionToken) {
		t.Errorf("session token with a credential: %v", err)
	}
	if _, err := e.auth.SessionToken(e.request(http.MethodGet, "/api/me", nil)); !errors.Is(err, appauth.ErrNoSessionToken) {
		t.Errorf("session token without a session: %v", err)
	}

	// A new Authenticator with the same key and stores, as after a
	// restart, keeps the session and can still use its tokens.
	restarted := e.newAuth(t)
	if _, err := restarted.Authenticate(e.request(http.MethodGet, "/api/me", withCookie(cookie))); err != nil {
		t.Fatalf("after a restart: %v", err)
	}
	if _, err := restarted.SessionToken(e.request(http.MethodGet, "/api/me", withCookie(cookie))); err != nil {
		t.Fatalf("session token after a restart: %v", err)
	}
}

func TestNoCredentials(t *testing.T) {
	e := newEnv(t)
	_, err := e.auth.Authenticate(e.request(http.MethodGet, "/api/me", nil))
	if !errors.Is(err, appauth.ErrUnauthenticated) {
		t.Fatalf("anonymous: %v", err)
	}
	if ch := appauth.Challenges(err); len(ch) != 1 || ch[0] != appauth.DPoPChallenge {
		t.Errorf("challenges: %v", ch)
	}
	var rpErr *requestprincipal.Error
	if !errors.As(err, &rpErr) || rpErr.Status != http.StatusUnauthorized {
		t.Errorf("protocol error: %v", err)
	}

	// The middleware sends the 401 itself.
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, e.request(http.MethodGet, "/api/me", nil))
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != appauth.DPoPChallenge {
		t.Errorf("middleware: %d %v", w.Code, w.Header())
	}
}

// A command-line tool signed in with publicclient calls the API with its
// DPoP-bound tokens; the same token sent as Bearer is refused.
func TestCommandLineTokens(t *testing.T) {
	e := newEnv(t)
	// The person has signed in to the application once, so it knows them.
	e.signIn()

	store := publicclient.FileStore{Path: filepath.Join(t.TempDir(), "credentials.json")}
	sess, err := publicclient.Login(t.Context(), publicclient.Config{Issuer: e.issuer, ClientID: "cli", Store: store}, e.cliBrowser())
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, e.app.URL+"/api/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := sess.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DPoP call: %d", resp.StatusCode)
	}

	creds, err := store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	bearer := e.request(http.MethodGet, "/api/me", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+creds.AccessToken)
	})
	_, err = e.auth.Authenticate(bearer)
	if !errors.Is(err, appauth.ErrUnauthenticated) {
		t.Fatalf("bound token as Bearer: %v", err)
	}
}

// cliBrowser plays the browser for publicclient.Login: it opens the
// authorization URL as the user and follows the redirect to the loopback
// callback.
func (e *env) cliBrowser() func(string) error {
	return func(authURL string) error {
		noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequestWithContext(e.t.Context(), http.MethodGet, authURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-Test-User", e.user)
		resp, err := noRedirect.Do(req)
		if err != nil {
			return err
		}
		if err := resp.Body.Close(); err != nil {
			return err
		}
		creq, err := http.NewRequestWithContext(e.t.Context(), http.MethodGet, resp.Header.Get("Location"), nil)
		if err != nil {
			return err
		}
		cresp, err := http.DefaultClient.Do(creq)
		if err != nil {
			return err
		}
		return cresp.Body.Close()
	}
}

func TestResourceMetadata(t *testing.T) {
	e := newEnv(t)
	w := httptest.NewRecorder()
	e.auth.ResourceMetadataHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, appauth.ResourceMetadataPath, nil))
	var md appauth.ResourceMetadata
	if err := json.Unmarshal(w.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	if md.Resource != e.app.URL || len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != e.issuer ||
		!md.DPoPBoundAccessTokensRequired {
		t.Errorf("metadata: %+v", md)
	}
}
