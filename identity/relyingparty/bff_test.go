package relyingparty

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type bffHarness struct {
	t     *testing.T
	fake  *fakeSystemAuth
	store *MemoryPrincipalStore
	bff   *BFF
}

func newHarness(t *testing.T) *bffHarness {
	t.Helper()
	fake := newFakeSystemAuth(t)
	store := NewMemoryPrincipalStore()
	b, err := NewBFF(BFFConfig{Client: fake.client(t), Principals: store})
	if err != nil {
		t.Fatalf("NewBFF: %v", err)
	}
	return &bffHarness{t: t, fake: fake, store: store, bff: b}
}

func (h *bffHarness) do(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.bff.ServeHTTP(w, req)
	return w
}

func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// start runs GET path and returns the SystemAuth authorization URL and
// the state cookie.
func (h *bffHarness) start(path string) (*url.URL, *http.Cookie) {
	h.t.Helper()
	w := h.do(httptest.NewRequest(http.MethodGet, path, nil))
	if w.Code != http.StatusFound {
		h.t.Fatalf("start %s: %d %s", path, w.Code, w.Body.String())
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		h.t.Fatal(err)
	}
	sc := cookieNamed(w.Result(), stateCookieName)
	if sc == nil {
		h.t.Fatal("no state cookie")
	}
	return u, sc
}

// login runs a full login and returns the callback response.
func (h *bffHarness) login(returnTo string) *httptest.ResponseRecorder {
	h.t.Helper()
	path := "/bff/auth/login"
	if returnTo != "" {
		path += "?return_to=" + url.QueryEscape(returnTo)
	}
	authURL, stateCookie := h.start(path)
	q := authURL.Query()
	code := h.fake.issueCode(q.Get("nonce"), q.Get("code_challenge"))
	req := httptest.NewRequest(http.MethodGet, "/bff/auth/callback?code="+code+"&state="+url.QueryEscape(q.Get("state")), nil)
	req.AddCookie(stateCookie)
	return h.do(req)
}

func (h *bffHarness) sessionCookie() *http.Cookie {
	h.t.Helper()
	w := h.login("")
	if w.Code != http.StatusFound {
		h.t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	c := cookieNamed(w.Result(), SessionCookieName)
	if c == nil {
		h.t.Fatal("no session cookie")
	}
	return c
}

func jsonPost(path string, cookie *http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", testAppURL)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}

func TestBFFLoginSessionLogout(t *testing.T) {
	h := newHarness(t)

	authURL, _ := h.start("/bff/auth/login?return_to=%2Fdashboard")
	q := authURL.Query()
	if !strings.HasPrefix(authURL.String(), h.fake.srv.URL+"/oauth/authorize?") ||
		q.Get("client_id") != testClientID || q.Get("redirect_uri") != testCallback ||
		q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" ||
		!strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("authorize URL = %s", authURL)
	}

	w := h.login("/dashboard")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/dashboard" {
		t.Fatalf("callback: %d %q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	sess := cookieNamed(w.Result(), SessionCookieName)
	if sess == nil || !sess.Secure || !sess.HttpOnly || sess.SameSite != http.SameSiteLaxMode || sess.Path != "/" || sess.Domain != "" {
		t.Fatalf("session cookie not hardened: %+v", sess)
	}
	for _, c := range w.Result().Cookies() {
		if strings.Contains(c.Value, "at-") || strings.Contains(c.Value, "rt-") {
			t.Errorf("SystemAuth token leaked into cookie %s", c.Name)
		}
	}

	// The principal was created and linked by sub.
	p, err := h.store.FindBySubject(t.Context(), h.fake.subject)
	if err != nil {
		t.Fatalf("principal not created: %v", err)
	}
	if err := h.store.AddMembership(p.ID, Membership{OrganizationID: "org-1", OrganizationName: "Acme", OrganizationSlug: "acme", Role: "owner", JoinedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	// GET /bff/session returns the user with memberships.
	req := httptest.NewRequest(http.MethodGet, "/bff/session", nil)
	req.AddCookie(sess)
	w = h.do(req)
	var status map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	user, _ := status["user"].(map[string]any)
	if w.Code != http.StatusOK || status["authenticated"] != true || status["user_id"] != p.ID || status["expires_at"] == nil || user == nil {
		t.Fatalf("session: %d %s", w.Code, w.Body.String())
	}
	ms, _ := user["memberships"].([]any)
	if user["email"] != "octo@example.com" || user["name"] != "Octo Cat" || len(ms) != 1 {
		t.Fatalf("user: %v", user)
	}
	m0, _ := ms[0].(map[string]any)
	for _, k := range []string{"id", "organization_id", "organization_name", "organization_slug", "role", "joined_at"} {
		if _, ok := m0[k]; !ok {
			t.Errorf("membership missing %q: %v", k, m0)
		}
	}

	// GET /bff/api/v1/users/me returns the same user.
	req = httptest.NewRequest(http.MethodGet, "/bff/api/v1/users/me", nil)
	req.AddCookie(sess)
	if w := h.do(req); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"organization_slug":"acme"`) {
		t.Errorf("users/me: %d %s", w.Code, w.Body.String())
	}

	// Logout requires a same-origin JSON request.
	bad := jsonPost("/bff/auth/logout", sess)
	bad.Header.Set("Origin", "https://evil.example.com")
	if w := h.do(bad); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin logout: %d", w.Code)
	}
	form := httptest.NewRequest(http.MethodPost, "/bff/auth/logout", strings.NewReader("a=b"))
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	form.AddCookie(sess)
	if w := h.do(form); w.Code != http.StatusForbidden {
		t.Errorf("form logout: %d", w.Code)
	}

	w = h.do(jsonPost("/bff/auth/logout", sess))
	if w.Code != http.StatusNoContent {
		t.Fatalf("logout: %d %s", w.Code, w.Body.String())
	}
	if c := cookieNamed(w.Result(), SessionCookieName); c == nil || c.MaxAge >= 0 {
		t.Errorf("cookie not cleared: %+v", c)
	}
	if len(h.fake.revoked) != 1 || !strings.HasPrefix(h.fake.revoked[0], "rt-") {
		t.Errorf("refresh token not revoked at SystemAuth: %v", h.fake.revoked)
	}
	req = httptest.NewRequest(http.MethodGet, "/bff/session", nil)
	req.AddCookie(sess)
	if w := h.do(req); !strings.Contains(w.Body.String(), `"authenticated":false`) {
		t.Errorf("session after logout: %s", w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/bff/api/v1/users/me", nil)
	req.AddCookie(sess)
	if w := h.do(req); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), `"code":"UNAUTHENTICATED"`) {
		t.Errorf("users/me after logout: %d %s", w.Code, w.Body.String())
	}
}

func TestBFFCallbackRejectsBadState(t *testing.T) {
	h := newHarness(t)
	authURL, stateCookie := h.start("/bff/auth/login")
	q := authURL.Query()
	code := h.fake.issueCode(q.Get("nonce"), q.Get("code_challenge"))

	// No state cookie (callback replayed into another browser).
	req := httptest.NewRequest(http.MethodGet, "/bff/auth/callback?code="+code+"&state="+url.QueryEscape(q.Get("state")), nil)
	if w := h.do(req); w.Code != http.StatusBadRequest {
		t.Errorf("missing cookie: %d", w.Code)
	}
	// Mismatched state.
	req = httptest.NewRequest(http.MethodGet, "/bff/auth/callback?code="+code+"&state=other", nil)
	req.AddCookie(stateCookie)
	if w := h.do(req); w.Code != http.StatusBadRequest {
		t.Errorf("mismatched state: %d", w.Code)
	}
	// Upstream error.
	req = httptest.NewRequest(http.MethodGet, "/bff/auth/callback?error=access_denied", nil)
	req.AddCookie(stateCookie)
	if w := h.do(req); w.Code != http.StatusBadRequest {
		t.Errorf("denied: %d", w.Code)
	}
	// State is single use.
	req = httptest.NewRequest(http.MethodGet, "/bff/auth/callback?code="+code+"&state="+url.QueryEscape(q.Get("state")), nil)
	req.AddCookie(stateCookie)
	if w := h.do(req); w.Code != http.StatusFound {
		t.Fatalf("valid callback: %d %s", w.Code, w.Body.String())
	}
	if w := h.do(req); w.Code != http.StatusBadRequest {
		t.Errorf("replayed state: %d", w.Code)
	}
}

func TestBFFRejectsBadIdentity(t *testing.T) {
	cases := map[string]struct {
		mutate func(*fakeSystemAuth)
		status int
	}{
		"wrong nonce":      {func(f *fakeSystemAuth) { f.idMutator = func(c map[string]any) { c["nonce"] = "x" } }, http.StatusUnauthorized},
		"wrong audience":   {func(f *fakeSystemAuth) { f.idMutator = func(c map[string]any) { c["aud"] = []string{"other"} } }, http.StatusUnauthorized},
		"userinfo sub":     {func(f *fakeSystemAuth) { f.userinfo = map[string]any{"sub": "someone-else"} }, http.StatusUnauthorized},
		"unverified email": {func(f *fakeSystemAuth) { f.verified = false }, http.StatusForbidden},
		"expired id token": {func(f *fakeSystemAuth) {
			f.idMutator = func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }
		}, http.StatusUnauthorized},
		"foreign issuer": {func(f *fakeSystemAuth) {
			f.idMutator = func(c map[string]any) { c["iss"] = "https://evil.example.com" }
		}, http.StatusUnauthorized},
		"azp with multi-aud": {func(f *fakeSystemAuth) {
			f.idMutator = func(c map[string]any) { c["aud"] = []string{testClientID, "other"} }
		}, http.StatusUnauthorized},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			tc.mutate(h.fake)
			w := h.login("")
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if cookieNamed(w.Result(), SessionCookieName) != nil {
				t.Error("session established for rejected identity")
			}
		})
	}
}

func TestBFFReturnToAndProviders(t *testing.T) {
	h := newHarness(t)
	for _, bad := range []string{"https://evil.example.com/", "//evil.example.com", "/\\evil.example.com", "javascript:alert(1)"} {
		w := h.do(httptest.NewRequest(http.MethodGet, "/bff/auth/login?return_to="+url.QueryEscape(bad), nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("return_to %q: %d", bad, w.Code)
		}
	}
	if w := h.do(httptest.NewRequest(http.MethodGet, "/bff/auth/login?return_to="+url.QueryEscape(testAppURL+"/x"), nil)); w.Code != http.StatusFound {
		t.Errorf("app-origin return_to rejected: %d", w.Code)
	}

	authURL, _ := h.start("/bff/auth/github?return_to=%2F")
	if authURL.Query().Get("idp_hint") != "github" {
		t.Errorf("idp_hint missing: %s", authURL)
	}
	if w := h.do(httptest.NewRequest(http.MethodGet, "/bff/auth/myspace", nil)); w.Code != http.StatusNotFound {
		t.Errorf("unknown provider: %d", w.Code)
	}
	if w := h.do(jsonPost("/bff/auth/login", nil)); w.Code != http.StatusNotImplemented {
		t.Errorf("password login: %d", w.Code)
	}
	if w := h.do(httptest.NewRequest(http.MethodGet, "/bff/session", nil)); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"authenticated":false`) {
		t.Errorf("anonymous session: %d %s", w.Code, w.Body.String())
	}
}

func TestBFFAccessTokenRefresh(t *testing.T) {
	h := newHarness(t)
	sess := h.sessionCookie()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sess)

	at, err := h.bff.AccessToken(req)
	if err != nil || !strings.HasPrefix(at, "at-") {
		t.Fatalf("AccessToken: %q %v", at, err)
	}

	// Expire the stored access token: the next call refreshes and rotates.
	h.bff.now = func() time.Time { return time.Now().Add(time.Hour) }
	stored, err := h.bff.cfg.Sessions.Get(t.Context(), sess.Value)
	if err != nil {
		t.Fatal(err)
	}
	at2, err := h.bff.AccessToken(req)
	if err != nil || at2 == at {
		t.Fatalf("refresh: %q %v", at2, err)
	}
	rotated, err := h.bff.cfg.Sessions.Get(t.Context(), sess.Value)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.RefreshToken == stored.RefreshToken {
		t.Error("refresh token not rotated in the session")
	}

	// SystemAuth rejecting the refresh (revoked family) ends the session.
	h.fake.mu.Lock()
	h.fake.refresh[rotated.RefreshToken] = false
	h.fake.mu.Unlock()
	if _, err := h.bff.AccessToken(req); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("rejected refresh: %v", err)
	}
	if _, err := h.bff.cfg.Sessions.Get(t.Context(), sess.Value); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("session survived rejected refresh: %v", err)
	}
}

func TestBFFRequireSession(t *testing.T) {
	h := newHarness(t)
	sess := h.sessionCookie()
	var got *AuthenticatedPrincipal
	protected := h.bff.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	protected.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/x", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", w.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.AddCookie(sess)
	w = httptest.NewRecorder()
	protected.ServeHTTP(w, req)
	if w.Code != http.StatusOK || got == nil || got.Method != AuthMethodSession || got.Subject != h.fake.subject {
		t.Fatalf("session principal: %d %+v", w.Code, got)
	}

	// Unsafe methods need a same-origin JSON request.
	post := httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader("a=b"))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(sess)
	w = httptest.NewRecorder()
	protected.ServeHTTP(w, post)
	if w.Code != http.StatusForbidden {
		t.Errorf("form POST: %d", w.Code)
	}
	w = httptest.NewRecorder()
	protected.ServeHTTP(w, jsonPost("/api/x", sess))
	if w.Code != http.StatusOK {
		t.Errorf("JSON POST: %d", w.Code)
	}
}

func TestNewBFFValidation(t *testing.T) {
	fake := newFakeSystemAuth(t)
	if _, err := NewBFF(BFFConfig{Principals: NewMemoryPrincipalStore()}); err == nil {
		t.Error("missing client accepted")
	}
	if _, err := NewBFF(BFFConfig{Client: fake.client(t)}); err == nil {
		t.Error("missing principals accepted")
	}
	if _, err := NewBFF(BFFConfig{Client: fake.client(t), Principals: NewMemoryPrincipalStore(), DefaultReturnTo: "https://evil.example.com"}); err == nil {
		t.Error("foreign default return_to accepted")
	}
	b, err := NewBFF(BFFConfig{Client: fake.client(t), Principals: NewMemoryPrincipalStore(), InsecureCookies: true, BasePath: "auth-bff/"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	b.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth-bff/auth/login", nil))
	if c := cookieNamed(w.Result(), insecureStateCookieName); w.Code != http.StatusFound || c == nil || c.Secure {
		t.Errorf("insecure mode: %d %+v", w.Code, c)
	}
}
