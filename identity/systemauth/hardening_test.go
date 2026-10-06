package systemauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
)

const (
	testVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	testRPCB      = "https://app.example.com/callback"
)

func authorizeURL(scope string) string {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", "spa")
	params.Set("redirect_uri", testRPCB)
	params.Set("scope", scope)
	params.Set("state", "rp-state-12345")
	params.Set("nonce", "rp-nonce-12345")
	params.Set("code_challenge", testChallenge)
	params.Set("code_challenge_method", "S256")
	return "/oauth/authorize?" + params.Encode()
}

// authorizeCode runs /oauth/authorize with the given request decorations and
// returns the code from the client redirect.
func authorizeCode(t *testing.T, s *Server, scope string, decorate func(*http.Request)) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, authorizeURL(scope), nil)
	decorate(req)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("authorize: %d %s", w.Code, w.Body.String())
	}
	cb, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %s", cb)
	}
	return code
}

func tokenRequest(t *testing.T, s *Server, form url.Values) (int, map[string]any) {
	t.Helper()
	form.Set("client_id", "spa")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("token response not JSON (%d): %s", w.Code, w.Body.String())
	}
	return w.Code, body
}

func exchangeCode(t *testing.T, s *Server, code string) map[string]any {
	t.Helper()
	status, body := tokenRequest(t, s, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRPCB},
		"code_verifier": {testVerifier},
	})
	if status != http.StatusOK {
		t.Fatalf("code exchange: %d %v", status, body)
	}
	return body
}

func refresh(t *testing.T, s *Server, refreshToken string) (int, map[string]any) {
	t.Helper()
	return tokenRequest(t, s, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
}

func introspectActive(t *testing.T, s *Server, token string) bool {
	t.Helper()
	_, ar, err := s.oauth2.IntrospectToken(context.Background(), token, fosite.AccessToken, s.Session(""))
	if err != nil {
		return false
	}
	return ar != nil
}

func headerUser(id string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("X-User-ID", id) }
}

func newRefreshTestServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	opts = append([]Option{WithSessionProvider(NewDefaultSessionProvider(WithSkipConsent(true)))}, opts...)
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID:            "spa",
			Type:          "public",
			Name:          "SPA",
			RedirectURIs:  []string{testRPCB},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
	}, opts...)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

// checkRefreshRotation drives rotation and reuse detection end to end.
func checkRefreshRotation(t *testing.T, s *Server) {
	t.Helper()
	subject := uuid.NewString()
	code := authorizeCode(t, s, "openid offline_access", headerUser(subject))
	first := exchangeCode(t, s, code)
	rt1, _ := first["refresh_token"].(string)
	at1, _ := first["access_token"].(string)
	if rt1 == "" || at1 == "" {
		t.Fatalf("missing tokens: %v", first)
	}

	// Rotation: a new refresh token is issued and the old access token retired.
	status, second := refresh(t, s, rt1)
	if status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, second)
	}
	rt2, _ := second["refresh_token"].(string)
	at2, _ := second["access_token"].(string)
	if rt2 == "" || rt2 == rt1 {
		t.Fatalf("refresh token not rotated: %v", second)
	}
	if !introspectActive(t, s, at2) {
		t.Fatal("rotated access token inactive")
	}
	_, ar, err := s.oauth2.IntrospectToken(context.Background(), at2, fosite.AccessToken, s.Session(""))
	if err != nil || ar.GetSession().GetSubject() != subject {
		t.Fatalf("subject not preserved across rotation: %v", err)
	}
	if introspectActive(t, s, at1) {
		t.Error("old access token still active after rotation")
	}

	// Reuse of the rotated token is rejected and revokes the whole family.
	status, body := refresh(t, s, rt1)
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("reuse: %d %v", status, body)
	}
	if introspectActive(t, s, at2) {
		t.Error("family access token still active after reuse")
	}
	if status, body := refresh(t, s, rt2); status == http.StatusOK {
		t.Fatalf("family refresh token still valid after reuse: %v", body)
	}
}

func TestRefreshRotationReuseDetectionMemory(t *testing.T) {
	checkRefreshRotation(t, newRefreshTestServer(t))
}

func TestRefreshRotationReuseDetectionEnt(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:refresh_rotation?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	owner := createTestUser(t, client)
	// The subject is a principal ID with no legacy User row.
	checkRefreshRotation(t, newRefreshTestServer(t, WithStorage(NewEntStorage(client, WithDefaultOwner(owner)))))
}

type recordingRevoker struct {
	*MemoryStorage
	revokedRefresh, revokedAccess []string
}

func (r *recordingRevoker) RevokeRefreshToken(ctx context.Context, id string) error {
	r.revokedRefresh = append(r.revokedRefresh, id)
	return r.MemoryStorage.RevokeRefreshToken(ctx, id)
}

func (r *recordingRevoker) RevokeAccessToken(ctx context.Context, id string) error {
	r.revokedAccess = append(r.revokedAccess, id)
	return r.MemoryStorage.RevokeAccessToken(ctx, id)
}

func TestRefreshFamilyAbsoluteLifetime(t *testing.T) {
	store := &recordingRevoker{MemoryStorage: NewMemoryStorage()}
	s := newRefreshTestServer(t, WithStorage(store))
	abs := s.config.Tokens.RefreshTokenAbsoluteLifetime.Duration()
	if abs != 30*24*time.Hour {
		t.Fatalf("default absolute lifetime = %v", abs)
	}

	newRequest := func(grant string, familyStart time.Time) *fosite.AccessRequest {
		ar := fosite.NewAccessRequest(&Session{DefaultSession: &openid.DefaultSession{}, FamilyIssuedAt: familyStart})
		ar.GrantTypes = fosite.Arguments{grant}
		ar.ID = uuid.NewString()
		ar.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().Add(7*24*time.Hour))
		return ar
	}

	// Within the family lifetime the new refresh token is capped at the deadline.
	start := time.Now().Add(-29 * 24 * time.Hour)
	ar := newRequest("refresh_token", start)
	if err := s.applyTokenFamilyLifetime(context.Background(), ar); err != nil {
		t.Fatalf("within lifetime: %v", err)
	}
	if got, want := ar.GetSession().GetExpiresAt(fosite.RefreshToken), start.Add(abs); !got.Equal(want) {
		t.Errorf("refresh expiry = %v, want capped at %v", got, want)
	}

	// Past the deadline the grant is rejected and the family revoked.
	ar = newRequest("refresh_token", time.Now().Add(-31*24*time.Hour))
	err := s.applyTokenFamilyLifetime(context.Background(), ar)
	if !errors.Is(err, fosite.ErrInvalidGrant) {
		t.Fatalf("expired family err = %v", err)
	}
	if len(store.revokedRefresh) != 1 || store.revokedRefresh[0] != ar.ID || len(store.revokedAccess) != 1 {
		t.Errorf("family not revoked: %v %v", store.revokedRefresh, store.revokedAccess)
	}

	// The first exchange starts the family clock.
	ar = newRequest("authorization_code", time.Time{})
	if err := s.applyTokenFamilyLifetime(context.Background(), ar); err != nil {
		t.Fatal(err)
	}
	if sess := ar.GetSession().(*Session); time.Since(sess.FamilyIssuedAt) > time.Minute {
		t.Errorf("family start not set: %v", sess.FamilyIssuedAt)
	}
}

func TestRefreshAbsoluteLifetimeValidation(t *testing.T) {
	_, err := NewEmbedded(Config{Issuer: testIssuer, Tokens: TokenConfig{
		RefreshTokenLifetime:         Duration(48 * time.Hour),
		RefreshTokenAbsoluteLifetime: Duration(24 * time.Hour),
	}})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("err = %v, want ErrInvalidConfig", err)
	}
	s, err := NewEmbedded(Config{Issuer: testIssuer, Tokens: TokenConfig{RefreshTokenLifetime: Duration(60 * 24 * time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.config.Tokens.RefreshTokenAbsoluteLifetime.Duration(); got != 60*24*time.Hour {
		t.Errorf("default absolute lifetime not raised to refresh lifetime: %v", got)
	}
}

func TestDefaultSessionProviderEscapesReturnURL(t *testing.T) {
	p := NewDefaultSessionProvider()
	ret := "/oauth/authorize?client_id=a&scope=openid email&redirect_uri=https://x/cb"
	for name, got := range map[string]string{"login": p.RedirectToLogin(ret), "consent": p.RedirectToConsent(ret)} {
		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if u.Query().Get("redirect") != ret || len(u.Query()) != 1 {
			t.Errorf("%s: redirect param = %q (query %v)", name, u.Query().Get("redirect"), u.Query())
		}
	}
	p = NewDefaultSessionProvider(WithLoginURL("/signin?tenant=x"))
	u, err := url.Parse(p.RedirectToLogin("/a?b=c"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("tenant") != "x" || u.Query().Get("redirect") != "/a?b=c" {
		t.Errorf("existing query not preserved: %s", u)
	}
}

// --- logout and consent (social login) ---

func newSocialFlowServer(t *testing.T, skipConsent bool) *Server {
	t.Helper()
	f := newFakeGitHub(t)
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID:            "spa",
			Type:          "public",
			Name:          "Example App",
			RedirectURIs:  []string{testRPCB},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
		SocialLogin: &SocialLoginConfig{
			AllowedRedirectOrigins: []string{"https://app.example.com"},
			SkipConsent:            skipConsent,
		},
	}, WithSocialConnector(f.connector()), WithPrincipalDirectory(NewMemoryPrincipalDirectory()))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

func socialSession(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	state, stateCookie := startLogin(t, s, "")
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusFound {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	sess := findCookie(t, w.Result(), LoginCookieName)
	if sess == nil {
		t.Fatal("no session cookie")
	}
	return sess
}

func withCookie(c *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(c) }
}

func postForm(s *Server, path, origin string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func TestLogoutRevokesSessionAndTokens(t *testing.T) {
	s := newSocialFlowServer(t, true)
	sess := socialSession(t, s)
	tokens := exchangeCode(t, s, authorizeCode(t, s, "openid offline_access", withCookie(sess)))
	at, _ := tokens["access_token"].(string)
	rt, _ := tokens["refresh_token"].(string)
	if !introspectActive(t, s, at) {
		t.Fatal("access token inactive before logout")
	}

	// Cross-origin and origin-less POSTs are rejected.
	for _, origin := range []string{"https://evil.example.com", ""} {
		if w := postForm(s, LogoutPath, origin, url.Values{}, sess); w.Code != http.StatusForbidden {
			t.Errorf("origin %q: status %d, want 403", origin, w.Code)
		}
	}
	// An open redirect target is rejected.
	if w := postForm(s, LogoutPath, testIssuer, url.Values{"return_to": {"https://evil.example.com/"}}, sess); w.Code != http.StatusBadRequest {
		t.Errorf("open redirect: status %d, want 400", w.Code)
	}

	// GET renders a confirmation form and never signs out.
	w := httptest.NewRecorder()
	get := httptest.NewRequest(http.MethodGet, LogoutPath+"?return_to=%2Fbye", nil)
	get.AddCookie(sess)
	s.ServeHTTP(w, get)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `method="post"`) {
		t.Fatalf("logout page: %d %s", w.Code, w.Body.String())
	}
	if !introspectActive(t, s, at) {
		t.Fatal("GET /logout revoked tokens")
	}

	w = postForm(s, LogoutPath, "https://app.example.com", url.Values{"return_to": {"https://app.example.com/bye"}}, sess)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "https://app.example.com/bye" {
		t.Fatalf("logout: %d %q", w.Code, w.Header().Get("Location"))
	}
	cleared := findCookie(t, w.Result(), LoginCookieName)
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("session cookie not cleared: %+v", cleared)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sess)
	if _, err := s.CurrentLoginSession(req); !errors.Is(err, ErrLoginSessionNotFound) {
		t.Errorf("session still valid after logout: %v", err)
	}
	if introspectActive(t, s, at) {
		t.Error("access token still active after logout")
	}
	if status, body := refresh(t, s, rt); status == http.StatusOK {
		t.Errorf("refresh token still valid after logout: %v", body)
	}

	// Logging out without a session just clears the cookie.
	if w := postForm(s, LogoutPath, testIssuer, url.Values{}); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Errorf("anonymous logout: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestConsentPage(t *testing.T) {
	s := newSocialFlowServer(t, false)
	sess := socialSession(t, s)
	authorize := authorizeURL("openid email")

	// Without consent, authorize sends the user to /consent.
	req := httptest.NewRequest(http.MethodGet, authorize, nil)
	req.AddCookie(sess)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusFound || loc.Path != ConsentPath || loc.Query().Get("return_to") != authorize {
		t.Fatalf("authorize without consent: %d %s", w.Code, loc)
	}

	// The consent page names the client and scopes and is frame-protected.
	req = httptest.NewRequest(http.MethodGet, loc.String(), nil)
	req.AddCookie(sess)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Example App") || !strings.Contains(body, "Read your email address") {
		t.Fatalf("consent page: %d %s", w.Code, body)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("consent page frameable")
	}
	csrf := consentCSRF(sess.Value)
	if !strings.Contains(body, csrf) {
		t.Fatal("csrf token missing from consent form")
	}

	// Signed-out users are sent to login first.
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, loc.String(), nil))
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), LoginPath+"?return_to=") {
		t.Errorf("signed-out consent: %d %q", w.Code, w.Header().Get("Location"))
	}

	// Only same-origin /oauth/authorize targets are accepted.
	w = httptest.NewRecorder()
	bad := httptest.NewRequest(http.MethodGet, ConsentPath+"?return_to="+url.QueryEscape("https://evil.example.com/oauth/authorize?client_id=spa"), nil)
	bad.AddCookie(sess)
	s.ServeHTTP(w, bad)
	if w.Code != http.StatusBadRequest {
		t.Errorf("foreign consent target: %d", w.Code)
	}

	form := url.Values{"return_to": {authorize}, "decision": {"allow"}, "csrf_token": {"forged"}}
	if w := postForm(s, ConsentPath, testIssuer, form, sess); w.Code != http.StatusForbidden {
		t.Errorf("forged csrf: %d", w.Code)
	}
	form.Set("csrf_token", csrf)
	if w := postForm(s, ConsentPath, "https://app.example.com", form, sess); w.Code != http.StatusForbidden {
		t.Errorf("consent posted from relying-party origin: %d", w.Code)
	}

	// Deny answers the client with access_denied.
	form.Set("decision", "deny")
	w = postForm(s, ConsentPath, testIssuer, form, sess)
	cb, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if cb.Host != "app.example.com" || cb.Query().Get("error") != "access_denied" || cb.Query().Get("state") != "rp-state-12345" {
		t.Fatalf("deny: %d %s", w.Code, cb)
	}

	// Allow records consent and returns to authorize, which now issues a code.
	form.Set("decision", "allow")
	w = postForm(s, ConsentPath, testIssuer, form, sess)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != authorize {
		t.Fatalf("allow: %d %q", w.Code, w.Header().Get("Location"))
	}
	authorizeCode(t, s, "openid email", withCookie(sess))

	// A broader request asks again.
	req = httptest.NewRequest(http.MethodGet, authorizeURL("openid email profile"), nil)
	req.AddCookie(sess)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if !strings.HasPrefix(w.Header().Get("Location"), ConsentPath) {
		t.Errorf("new scope did not require consent: %q", w.Header().Get("Location"))
	}
}

func TestMemoryConsentStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryConsentStore()
	ok, err := store.HasConsent(ctx, "p", "c", []string{"openid"})
	if err != nil || ok {
		t.Fatalf("empty store: %v %v", ok, err)
	}
	if err := store.SaveConsent(ctx, "p", "c", []string{"openid"}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveConsent(ctx, "p", "c", []string{"email"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.HasConsent(ctx, "p", "c", []string{"openid", "email"}); err != nil || !ok {
		t.Errorf("accumulated scopes: %v %v", ok, err)
	}
	if ok, err := store.HasConsent(ctx, "p", "other", []string{"openid"}); err != nil || ok {
		t.Errorf("consent leaked across clients: %v %v", ok, err)
	}
	if err := store.RevokeConsent(ctx, "p", "c"); err != nil {
		t.Fatal(err)
	}
	if ok, err := store.HasConsent(ctx, "p", "c", nil); err != nil || ok {
		t.Errorf("revoked consent still present: %v %v", ok, err)
	}
}
