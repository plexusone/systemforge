package publicclient_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/grokify/goauth/dpop"

	"github.com/plexusone/systemforge/identity/publicclient"
	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/session/middleware"
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

// env is a SystemAuth that requires DPoP nonces, a public client "cli"
// registered for the loopback redirect, and an API that accepts the CLI's
// DPoP-bound tokens.
type env struct {
	issuer string
	user   string
	api    string
	store  publicclient.FileStore
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := t.Context()
	var sa *systemauth.Server
	saSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sa.ServeHTTP(w, r) }))
	t.Cleanup(saSrv.Close)
	var err error
	sa, err = systemauth.NewEmbedded(systemauth.Config{
		Issuer: saSrv.URL,
		Clients: []systemauth.ClientConfig{{
			ID: "cli", Type: "public", Name: "CLI",
			RedirectURIs:  []string{publicclient.RegisteredRedirectURI},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
		Features: systemauth.FeatureConfig{RequirePKCE: true, EnableJWTAccessTokens: true},
		DPoP:     systemauth.DPoPConfig{RequireNonce: true, NonceSecret: strings.Repeat("s", 32)},
	}, systemauth.WithSessionProvider(headerSession{}))
	if err != nil {
		t.Fatal(err)
	}
	human := &systemauth.HumanPrincipal{Email: "dev@example.com", EmailVerified: true, Active: true}
	if err := sa.Storage().CreateHuman(ctx, human); err != nil {
		t.Fatal(err)
	}

	// The API: an app whose own client is "api", accepting the CLI's
	// tokens with DPoP proofs, and refusing Bearer.
	verifier, err := relyingparty.NewClient(ctx, relyingparty.Config{
		Issuer: saSrv.URL, ClientID: "api", RedirectURL: "https://api.example.com/callback",
		AcceptedClientIDs: []string{"cli"},
	})
	if err != nil {
		t.Fatal(err)
	}
	principals := relyingparty.NewMemoryPrincipalStore()
	if _, err := principals.AddPrincipal(relyingparty.Principal{SFPrincipalID: human.ID.String(), Email: "dev@example.com", Active: true}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	apiSrv := httptest.NewServer(mux)
	t.Cleanup(apiSrv.Close)
	mux.Handle("/whoami", relyingparty.BearerMiddleware(relyingparty.BearerConfig{
		Tokens: verifier, Principals: principals,
		DPoP: &relyingparty.DPoPConfig{ReplayCache: middleware.NewMemoryReplayCache(), BaseURL: apiSrv.URL},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := relyingparty.PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusInternalServerError)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := fmt.Fprintf(w, "%s %s", p.Subject, body); err != nil {
			t.Error(err)
		}
	})))
	return &env{
		issuer: saSrv.URL, user: human.ID.String(), api: apiSrv.URL + "/whoami",
		store: publicclient.FileStore{Path: filepath.Join(t.TempDir(), "cfg", "credentials.json")},
	}
}

func (e *env) config() publicclient.Config {
	return publicclient.Config{Issuer: e.issuer, ClientID: "cli", Store: e.store}
}

// browser plays the person's browser: it opens the authorization URL as
// the signed-in user and follows SystemAuth's redirect to the loopback
// callback.
func (e *env) browser(t *testing.T) func(string) error {
	return func(authURL string) error {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("X-Test-User", e.user)
		noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := noRedirect.Do(req)
		if err != nil {
			return err
		}
		if err := resp.Body.Close(); err != nil {
			return err
		}
		cb := resp.Header.Get("Location")
		if !strings.HasPrefix(cb, "http://127.0.0.1:") {
			return fmt.Errorf("authorize: %d, redirect %q", resp.StatusCode, cb)
		}
		creq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, cb, nil)
		if err != nil {
			return err
		}
		cresp, err := http.DefaultClient.Do(creq)
		if err != nil {
			return err
		}
		if err := cresp.Body.Close(); err != nil {
			return err
		}
		if cresp.StatusCode != http.StatusOK {
			return fmt.Errorf("callback: %d", cresp.StatusCode)
		}
		return nil
	}
}

func call(t *testing.T, c *http.Client, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// expire marks the stored access token as expired, as if time had passed.
func (e *env) expire(t *testing.T) {
	t.Helper()
	c, err := e.store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c.Expiry = time.Now().Add(-time.Minute)
	if err := e.store.Save(t.Context(), c); err != nil {
		t.Fatal(err)
	}
}

// TestLoginAndCallAPI runs a login against SystemAuth and calls an API
// with the session: the tokens are bound to the session's key, requests
// carry proofs (with the nonces SystemAuth requires at its token
// endpoint), the credentials persist with owner-only permissions, and an
// expired access token is refreshed with a rotated refresh token.
func TestLoginAndCallAPI(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	s, err := publicclient.Login(ctx, e.config(), e.browser(t))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if id := s.Identity(); id.Subject != e.user || id.Email != "dev@example.com" {
		t.Errorf("identity: %+v", id)
	}
	if code, body := call(t, s.HTTPClient(), e.api, "hello"); code != http.StatusOK || body != e.user+" hello" {
		t.Fatalf("API call: %d %s", code, body)
	}

	stored, err := e.store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RefreshToken == "" || stored.AccessToken == "" || stored.Issuer != e.issuer || len(stored.DPoPKey) == 0 {
		t.Fatalf("stored credentials: %+v", stored)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(e.store.Path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("credentials file mode: %v %v", info.Mode().Perm(), err)
		}
	}

	// The stored token is useless as a Bearer token.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.api, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+stored.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("stored token as Bearer: %d", resp.StatusCode)
	}

	// A later run opens the stored session and refreshes the expired
	// access token, rotating the refresh token.
	e.expire(t)
	later, err := publicclient.Open(ctx, e.config())
	if err != nil {
		t.Fatal(err)
	}
	if later.DPoPThumbprint() != s.DPoPThumbprint() {
		t.Error("the stored session has another key")
	}
	if code, body := call(t, later.HTTPClient(), e.api, "again"); code != http.StatusOK || body != e.user+" again" {
		t.Fatalf("API call after refresh: %d %s", code, body)
	}
	refreshed, err := e.store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.RefreshToken == stored.RefreshToken || refreshed.AccessToken == stored.AccessToken || time.Until(refreshed.Expiry) < time.Minute {
		t.Errorf("refresh did not rotate the tokens: %+v", refreshed)
	}
}

// TestSharedStore checks two processes sharing a store: when both find the
// access token expired, the second adopts the tokens the first refreshed
// instead of redeeming the old refresh token again, which SystemAuth would
// take for theft and answer by revoking the family.
func TestSharedStore(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if _, err := publicclient.Login(ctx, e.config(), e.browser(t)); err != nil {
		t.Fatalf("login: %v", err)
	}
	e.expire(t)
	first, err := publicclient.Open(ctx, e.config())
	if err != nil {
		t.Fatal(err)
	}
	second, err := publicclient.Open(ctx, e.config())
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range []*publicclient.Session{first, second} {
		if code, body := call(t, s.HTTPClient(), e.api, "x"); code != http.StatusOK {
			t.Fatalf("process %d: %d %s", i+1, code, body)
		}
	}
	// The family is intact: a third run refreshes again.
	e.expire(t)
	third, err := publicclient.Open(ctx, e.config())
	if err != nil {
		t.Fatal(err)
	}
	if code, body := call(t, third.HTTPClient(), e.api, "x"); code != http.StatusOK {
		t.Fatalf("refresh after the shared refresh: %d %s", code, body)
	}
}

// TestLogout checks that logging out revokes the refresh token and deletes
// the credentials.
func TestLogout(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	s, err := publicclient.Login(ctx, e.config(), e.browser(t))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	stored, err := e.store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Logout(ctx); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := publicclient.Open(ctx, e.config()); !errors.Is(err, publicclient.ErrNotLoggedIn) {
		t.Errorf("open after logout: %v", err)
	}
	// The revoked refresh token no longer refreshes, even with its key.
	if err := e.store.Save(ctx, stored); err != nil {
		t.Fatal(err)
	}
	e.expire(t)
	again, err := publicclient.Open(ctx, e.config())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.AccessToken(ctx); err == nil {
		t.Error("a revoked refresh token refreshed")
	}
}

// TestLoginRefusals checks a login SystemAuth refuses and one that is
// cancelled.
func TestLoginRefusals(t *testing.T) {
	e := newEnv(t)
	cfg := e.config()
	// A person who declines: SystemAuth redirects to the client with
	// error=access_denied and this login's state.
	denied := func(authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		q := u.Query()
		cb := q.Get("redirect_uri") + "?error=access_denied&state=" + url.QueryEscape(q.Get("state"))
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, cb, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	if _, err := publicclient.Login(t.Context(), cfg, denied); err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("declined login: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err := publicclient.Login(ctx, cfg, func(string) error { return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("abandoned login: %v", err)
	}
	if _, err := e.store.Load(t.Context()); !errors.Is(err, publicclient.ErrNotLoggedIn) {
		t.Errorf("a refused login stored credentials: %v", err)
	}
}

// TestFileStore checks the file store: no file is ErrNotLoggedIn, a file
// others can read is refused, and the lock excludes a second holder until
// it is released.
func TestFileStore(t *testing.T) {
	ctx := t.Context()
	fs := publicclient.FileStore{Path: filepath.Join(t.TempDir(), "credentials.json")}
	if _, err := fs.Load(ctx); !errors.Is(err, publicclient.ErrNotLoggedIn) {
		t.Fatalf("missing file: %v", err)
	}
	if err := fs.Save(ctx, &publicclient.Credentials{Issuer: "https://auth.example.com", ClientID: "cli", AccessToken: "at"}); err != nil {
		t.Fatal(err)
	}
	if c, err := fs.Load(ctx); err != nil || c.AccessToken != "at" {
		t.Fatalf("load: %+v %v", c, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(fs.Path, 0o644); err != nil { //nolint:gosec // G302: the test makes the file readable by others on purpose
			t.Fatal(err)
		}
		if _, err := fs.Load(ctx); err == nil || !strings.Contains(err.Error(), "accessible by others") {
			t.Errorf("world-readable file: %v", err)
		}
		if err := os.Chmod(fs.Path, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	unlock, err := fs.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waiting, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if _, err := fs.Lock(waiting); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("second lock while held: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	unlock, err = fs.Lock(ctx)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}

	if err := fs.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if err := fs.Delete(ctx); err != nil {
		t.Errorf("deleting nothing: %v", err)
	}
}

// lockingStore is a FileStore whose lock counts its holders and can fail
// to release.
type lockingStore struct {
	publicclient.FileStore
	locks     int
	unlockErr error
}

func (l *lockingStore) Lock(ctx context.Context) (func() error, error) {
	unlock, err := l.FileStore.Lock(ctx)
	if err != nil {
		return nil, err
	}
	l.locks++
	return func() error { return errors.Join(unlock(), l.unlockErr) }, nil
}

// TestStoreLock checks that a refresh reports a failure to release the
// store's lock, and that logout holds the lock.
func TestStoreLock(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if _, err := publicclient.Login(ctx, e.config(), e.browser(t)); err != nil {
		t.Fatalf("login: %v", err)
	}
	ls := &lockingStore{FileStore: e.store, unlockErr: errors.New("unlock failed")}
	cfg := e.config()
	cfg.Store = ls

	e.expire(t)
	s, err := publicclient.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AccessToken(ctx); err == nil || !strings.Contains(err.Error(), "unlock failed") {
		t.Errorf("refresh with a failing unlock: %v", err)
	}

	ls.unlockErr, ls.locks = nil, 0
	if err := s.Logout(ctx); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if ls.locks != 1 {
		t.Errorf("logout took the store's lock %d times, want 1", ls.locks)
	}
}

// trackedBody records whether it was closed.
type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error {
	b.closed = true
	return nil
}

// TestTransportClosesBody checks the RoundTripper contract: a request that
// cannot be sent, here because the access token expired and there is no
// refresh token, has its body closed.
func TestTransportClosesBody(t *testing.T) {
	ctx := t.Context()
	key, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := key.SerializeJSON()
	if err != nil {
		t.Fatal(err)
	}
	store := publicclient.FileStore{Path: filepath.Join(t.TempDir(), "credentials.json")}
	if err := store.Save(ctx, &publicclient.Credentials{
		Issuer: "https://auth.example.com", ClientID: "cli", DPoPKey: serialized,
		AccessToken: "expired", Expiry: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	s, err := publicclient.Open(ctx, publicclient.Config{
		Issuer: "https://auth.example.com", ClientID: "cli", Store: store,
		Metadata: &relyingparty.Metadata{ //nolint:gosec // G101: endpoint URLs, not credentials
			Issuer:                "https://auth.example.com",
			AuthorizationEndpoint: "https://auth.example.com/oauth/authorize",
			TokenEndpoint:         "https://auth.example.com/oauth/token",
			JWKSURI:               "https://auth.example.com/.well-known/jwks.json",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := &trackedBody{Reader: strings.NewReader("payload")}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.example.com/x", body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Transport(nil).RoundTrip(req); !errors.Is(err, publicclient.ErrNotLoggedIn) {
		t.Errorf("round trip without a usable token: %v", err)
	}
	if !body.closed {
		t.Error("the request body was not closed")
	}
}
