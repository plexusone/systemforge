package relyingparty_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// headerSession authenticates SystemAuth requests by a test header and
// returns a verified email, standing in for SystemAuth's social login.
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

// TestInteropWithSystemAuth runs the relying party against a real
// SystemAuth server: login, ID token + JWKS verification, userinfo, JWT
// access tokens through BearerMiddleware, refresh rotation and logout
// revocation.
func TestInteropWithSystemAuth(t *testing.T) {
	var sa *systemauth.Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sa.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)

	const callback = "https://app.example.com/bff/auth/callback"
	var err error
	sa, err = systemauth.NewEmbedded(systemauth.Config{
		Issuer: srv.URL,
		Clients: []systemauth.ClientConfig{{
			ID: "app", Type: "public", Name: "App",
			RedirectURIs:  []string{callback},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
		Features: systemauth.FeatureConfig{RequirePKCE: true, EnableJWTAccessTokens: true},
	}, systemauth.WithSessionProvider(headerSession{}))
	if err != nil {
		t.Fatal(err)
	}

	ctx := t.Context()
	client, err := relyingparty.NewClient(ctx, relyingparty.Config{Issuer: srv.URL, ClientID: "app", RedirectURL: callback})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	store := relyingparty.NewMemoryPrincipalStore()
	bff, err := relyingparty.NewBFF(relyingparty.BFFConfig{Client: client, Principals: store})
	if err != nil {
		t.Fatal(err)
	}

	// 1. The app starts the login.
	w := httptest.NewRecorder()
	bff.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/bff/auth/login?return_to=%2Fhome", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("login: %d", w.Code)
	}
	authURL := w.Header().Get("Location")
	stateCookie := w.Result().Cookies()[0]

	// 2. The (already signed-in) user is sent back with a code.
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	subject := uuid.NewString()
	authReq.Header.Set("X-Test-User", subject)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Do(authReq)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(cb.String(), callback) {
		t.Fatalf("authorize: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// 3. The callback verifies the ID token and creates the session.
	req := httptest.NewRequest(http.MethodGet, "/bff/auth/callback?"+cb.RawQuery, nil)
	req.AddCookie(stateCookie)
	w = httptest.NewRecorder()
	bff.ServeHTTP(w, req)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/home" {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	var sessCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == relyingparty.SessionCookieName {
			sessCookie = c
		}
	}
	p, err := store.FindBySubject(ctx, subject)
	if err != nil || p.Email != "dev@example.com" || p.SFPrincipalID != subject {
		t.Fatalf("principal: %+v %v", p, err)
	}

	// 4. The SystemAuth JWT access token authenticates API calls.
	sessReq := httptest.NewRequest(http.MethodGet, "/", nil)
	sessReq.AddCookie(sessCookie)
	at, err := bff.AccessToken(sessReq)
	if err != nil {
		t.Fatal(err)
	}
	api := relyingparty.BearerMiddleware(relyingparty.BearerConfig{Tokens: client, Principals: store})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got, ok := relyingparty.PrincipalFromContext(r.Context()); !ok || got.ID != p.ID {
				t.Errorf("api principal: %+v", got)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
	apiReq := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	apiReq.Header.Set("Authorization", "Bearer "+at)
	w = httptest.NewRecorder()
	api.ServeHTTP(w, apiReq)
	if w.Code != http.StatusNoContent {
		t.Fatalf("api with SystemAuth JWT: %d %s", w.Code, w.Body.String())
	}

	// 5. Refresh rotates the SystemAuth refresh token.
	sess, _, _, err := bff.CurrentSession(sessReq)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := client.Refresh(ctx, sess.RefreshToken)
	if err != nil || tok.RefreshToken == "" || tok.RefreshToken == sess.RefreshToken {
		t.Fatalf("refresh: %v", err)
	}
	if _, err := client.Refresh(ctx, sess.RefreshToken); err == nil {
		t.Error("reused refresh token accepted")
	}
	if _, err := client.Refresh(ctx, tok.RefreshToken); err == nil {
		t.Error("token family survived reuse")
	}

	// 6. Logout revokes at SystemAuth (the family is already revoked here;
	// revocation of an inactive token still succeeds).
	logout := httptest.NewRequest(http.MethodPost, "/bff/auth/logout", strings.NewReader("{}"))
	logout.Header.Set("Content-Type", "application/json")
	logout.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	bff.ServeHTTP(w, logout)
	if w.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", w.Code)
	}
	if _, _, _, err := bff.CurrentSession(sessReq); err == nil {
		t.Error("session survived logout")
	}
}
