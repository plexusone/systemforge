package systemauthsvc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"golang.org/x/oauth2"

	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/oauthclient"
	"github.com/plexusone/systemforge/identity/signupgate"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// fakeUpstream is a GitHub stand-in whose signed-in user can be changed.
type fakeUpstream struct {
	srv   *httptest.Server
	mu    sync.Mutex
	id    int
	email string
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	f := &fakeUpstream{id: 1, email: "ada@example.com"}
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(v); err != nil {
			t.Errorf("encode: %v", err)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, _ *http.Request) {
		write(w, map[string]any{"access_token": "gh-token", "token_type": "bearer"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		write(w, map[string]any{"id": f.id, "login": "user", "name": "User"})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		write(w, []map[string]any{{"email": f.email, "primary": true, "verified": true}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeUpstream) as(id int, email string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.id, f.email = id, email
}

func (f *fakeUpstream) connector(issuer string) *oauthclient.Connector {
	c := oauthclient.NewGitHubConnector(oauthclient.ProviderConfig{
		ClientID: "gh", ClientSecret: "gh-secret", RedirectURL: issuer + "/login/github/callback",
	})
	c.OAuth2.Endpoint = oauth2.Endpoint{AuthURL: f.srv.URL + "/authorize", TokenURL: f.srv.URL + "/login/oauth/access_token"}
	c.APIURL = f.srv.URL
	c.HTTPClient = f.srv.Client()
	return c
}

func cookieNamed(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func get(h http.Handler, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// signIn runs a GitHub login with the given extra cookies and returns the
// callback's response.
func signIn(t *testing.T, h http.Handler, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	start := get(h, "/login/github")
	if start.Code != http.StatusFound {
		t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	loc, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	var stateCookie *http.Cookie
	for _, c := range start.Result().Cookies() {
		if strings.Contains(c.Name, "oauth_state") {
			stateCookie = c
		}
	}
	return get(h, "/login/github/callback?code=upstream&state="+url.QueryEscape(loc.Query().Get("state")),
		append([]*http.Cookie{stateCookie}, cookies...)...)
}

func TestInviteCodeAdmitsUpToItsLimitAndTheAPIServes(t *testing.T) {
	const issuer = "https://auth.example.com"
	f := newFakeUpstream(t)
	cfg := &systemauthsvc.Config{
		Issuer:   issuer,
		Tokens:   prodTokens,
		DPoP:     prodDPoP,
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		SocialLogin: &systemauth.SocialLoginConfig{
			SkipConsent:            true,
			AllowedRedirectOrigins: []string{"https://app.example.com"},
		},
	}
	s, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{
		SigningKey: testKey(t), Logger: discardLogger(), Migrate: true,
		InviteOnly: true, SignupCodes: true, SignupAPI: true,
		SignupPage:    systemauth.SignupPage{ReturnTo: "https://app.example.com/"},
		ServerOptions: []systemauth.Option{systemauth.WithSocialConnector(f.connector(issuer))},
	})
	if err != nil {
		t.Fatal(err)
	}
	closeService(t, s)
	h := s.Handler()

	created, code, err := s.SignupCodes().CreateCode(t.Context(), signupgate.CodeOptions{Kind: signupgate.CodeOperator, Label: "launch", MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	page := get(h, systemauth.SignupPath+"?code="+url.QueryEscape(code))
	codeCookie := cookieNamed(page.Result(), "__Host-sf_signup_code")
	if page.Code != http.StatusOK || codeCookie == nil || !strings.Contains(page.Body.String(), "/login/github") {
		t.Fatalf("sign-up page: %d cookie %v %s", page.Code, codeCookie, page.Body)
	}

	// Ada signs in with the code: her account is created and the use
	// recorded.
	cb := signIn(t, h, codeCookie)
	if cb.Code != http.StatusFound {
		t.Fatalf("ada's sign-in: %d %s", cb.Code, cb.Body)
	}
	session := cookieNamed(cb.Result(), systemauth.LoginCookieName)
	if session == nil {
		t.Fatal("no login session for ada")
	}
	reds, err := s.SignupCodes().Redemptions(t.Context(), signupgate.RedemptionFilter{CodeID: &created.ID})
	if err != nil || len(reds) != 1 || reds[0].Email != "ada@example.com" {
		t.Fatalf("redemptions = %+v, %v", reds, err)
	}

	// Grace brings the same, now used-up code and is refused.
	f.as(2, "grace@example.com")
	if cb := signIn(t, h, codeCookie); cb.Code != http.StatusSeeOther || !strings.Contains(cb.Header().Get("Location"), "invite_required") {
		t.Fatalf("grace with a used-up code: %d %s", cb.Code, cb.Header().Get("Location"))
	}

	// The invite API answers the SystemAuth session.
	if rec := get(h, systemauthsvc.SignupAPIPath+"/settings"); rec.Code != http.StatusUnauthorized {
		t.Errorf("API without a session: %d", rec.Code)
	}
	if rec := get(h, systemauthsvc.SignupAPIPath+"/me/invites", session); rec.Code != http.StatusOK {
		t.Errorf("member route with ada's session: %d %s", rec.Code, rec.Body)
	}
	if rec := get(h, systemauthsvc.SignupAPIPath+"/admin/codes", session); rec.Code != http.StatusForbidden {
		t.Errorf("admin route for a non-admin: %d", rec.Code)
	}
	if _, err := s.EntClient().Human.Update().Where(human.EmailEQ("ada@example.com")).SetIsPlatformAdmin(true).Save(t.Context()); err != nil {
		t.Fatal(err)
	}
	rec := get(h, systemauthsvc.SignupAPIPath+"/admin/codes", session)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), created.ID.String()) {
		t.Errorf("admin route for an admin: %d %s", rec.Code, rec.Body)
	}
}

func TestSignupCodeOptionsNeedInviteOnly(t *testing.T) {
	for _, opts := range []systemauthsvc.Options{
		{SignupCodes: true},
		{InviteOnly: true, SignupAPI: true},
	} {
		cfg := &systemauthsvc.Config{Issuer: "https://auth.example.com", Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)}}
		opts.SigningKey, opts.Logger, opts.Migrate = testKey(t), discardLogger(), true
		if s, err := systemauthsvc.New(t.Context(), cfg, opts); err == nil {
			closeService(t, s)
			t.Errorf("options %+v accepted", opts)
		}
	}
}
