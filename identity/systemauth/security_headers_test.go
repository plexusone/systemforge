package systemauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/oauthclient"
)

// checkSecurityHeaders asserts the headers every SystemAuth response
// carries, and that the content security policy's form-action is 'self'
// followed by formTargets.
func checkSecurityHeaders(t *testing.T, name string, w *httptest.ResponseRecorder, formTargets ...string) {
	t.Helper()
	h := w.Header()
	want := map[string]string{
		"Content-Security-Policy":   contentSecurityPolicy(formTargets...),
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "same-origin",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("%s: %s = %q, want %q", name, k, got, v)
		}
	}
	csp := h.Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "object-src 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("%s: CSP %q lacks %q", name, csp, directive)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("%s: CSP allows inline code: %q", name, csp)
	}
}

// checkNoInlineCode asserts that a page needs nothing the policy blocks:
// no script, no style element or attribute, no event handler attribute.
func checkNoInlineCode(t *testing.T, name string, w *httptest.ResponseRecorder) {
	t.Helper()
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("%s: not an HTML page: %d %q %s", name, w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	body := strings.ToLower(w.Body.String())
	for _, banned := range []string{"<script", "<style", " style=", " onclick=", " onsubmit=", " onload=", "javascript:", "<link", "<iframe", "<object"} {
		if strings.Contains(body, banned) {
			t.Errorf("%s: page contains %q, which the content security policy blocks", name, banned)
		}
	}
}

func serve(s *Server, r *http.Request, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// TestSecurityHeadersOnLogoutAndConsent covers the logout and consent
// pages, whose forms redirect to another origin, and the redirects and
// errors around them.
func TestSecurityHeadersOnLogoutAndConsent(t *testing.T) {
	s := newSocialFlowServer(t, PartyThird)
	sess := socialSession(t, s)

	logout := serve(s, httptest.NewRequest(http.MethodGet, LogoutPath, nil), sess)
	if logout.Code != http.StatusOK {
		t.Fatalf("logout page: %d", logout.Code)
	}
	// Signing out redirects to an allowed origin.
	checkSecurityHeaders(t, "logout page", logout, "https://app.example.com", "https://auth.example.com")
	checkNoInlineCode(t, "logout page", logout)

	authorize := serve(s, httptest.NewRequest(http.MethodGet, authorizeURL("openid email"), nil), sess)
	if authorize.Code != http.StatusFound {
		t.Fatalf("authorize: %d", authorize.Code)
	}
	checkSecurityHeaders(t, "authorize redirect", authorize)
	consent := serve(s, httptest.NewRequest(http.MethodGet, authorize.Header().Get("Location"), nil), sess)
	if consent.Code != http.StatusOK {
		t.Fatalf("consent page: %d %s", consent.Code, consent.Body.String())
	}
	// Both decisions end at the client's redirect URI.
	checkSecurityHeaders(t, "consent page", consent, "https://app.example.com")
	checkNoInlineCode(t, "consent page", consent)

	// Error pages and responses outside the pages carry the defaults.
	for name, r := range map[string]*http.Request{
		"logout error":  httptest.NewRequest(http.MethodGet, LogoutPath+"?return_to=https%3A%2F%2Fevil.example.com%2F", nil),
		"consent error": httptest.NewRequest(http.MethodGet, ConsentPath+"?return_to=%2Felsewhere", nil),
		"not found":     httptest.NewRequest(http.MethodGet, "/no-such-page", nil),
		"discovery":     httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil),
		"login":         httptest.NewRequest(http.MethodGet, LoginPath, nil),
	} {
		checkSecurityHeaders(t, name, serve(s, r))
	}
	// A consent decision ends at the client with no referrer.
	decision := postForm(s, ConsentPath, testIssuer, url.Values{
		"return_to": {authorizeURL("openid email")}, "csrf_token": {consentCSRF(sess.Value)}, "decision": {"deny"},
	}, sess)
	if decision.Code < 300 || decision.Code > 399 || !strings.HasPrefix(decision.Header().Get("Location"), testRPCB) {
		t.Fatalf("deny: %d %q", decision.Code, decision.Header().Get("Location"))
	}
	checkSecurityHeaders(t, "consent decision", decision)
}

// TestSecurityHeadersOnSignupPages covers the login chooser and the
// sign-up, sign-up code, waitlist and age question pages.
func TestSecurityHeadersOnSignupPages(t *testing.T) {
	f := newFakeGitHub(t)
	google := oauthclient.NewGoogleConnector(oauthclient.ProviderConfig{
		ClientID: "g-client", ClientSecret: "g-secret", RedirectURL: testIssuer + "/login/google/callback",
	})
	s := newAgeServer(t, f, NewMemoryPrincipalDirectory(),
		WithSocialConnector(google),
		WithSignupCodes(stubCodes{}, SignupPage{ReturnTo: "https://app.example.com/start"}),
		WithSignupWaitlist(&stubWaitlist{}, WaitlistPage{}),
	)

	pages := map[string]*http.Request{
		"login chooser":        httptest.NewRequest(http.MethodGet, LoginPath, nil),
		"sign-up page":         httptest.NewRequest(http.MethodGet, SignupPath+"?code=good-code", nil),
		"invalid sign-up code": httptest.NewRequest(http.MethodGet, SignupPath+"?code=old-code", nil),
		"waitlist page":        httptest.NewRequest(http.MethodGet, SignupWaitlistPath+"?error=invite_required", nil),
	}
	for name, r := range pages {
		w := serve(s, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body.String())
		}
		checkSecurityHeaders(t, name, w)
		checkNoInlineCode(t, name, w)
	}

	joined := postForm(s, SignupWaitlistPath, testIssuer, url.Values{"email": {"a@example.com"}, "consent": {"yes"}})
	if joined.Code != http.StatusOK {
		t.Fatalf("waitlist join: %d %s", joined.Code, joined.Body.String())
	}
	checkSecurityHeaders(t, "waitlist thanks", joined)
	checkNoInlineCode(t, "waitlist thanks", joined)

	// The age answer restarts the upstream login and continues wherever
	// the sign-in returns.
	pending := askedAge(t, s, "")
	age := getAgePage(s, pending)
	if age.Code != http.StatusOK || !strings.Contains(age.Body.String(), `<form method="post"`) {
		t.Fatalf("age page: %d %s", age.Code, age.Body.String())
	}
	checkSecurityHeaders(t, "age page", age, "https:")
	checkNoInlineCode(t, "age page", age)
	expired := getAgePage(s)
	checkSecurityHeaders(t, "expired age page", expired, "https:")
	checkNoInlineCode(t, "expired age page", expired)
}

// TestSecurityHeadersWithoutHTTPS verifies that HSTS is sent only when the
// issuer is https.
func TestSecurityHeadersWithoutHTTPS(t *testing.T) {
	s, err := NewEmbedded(Config{Issuer: "http://localhost:8081"})
	if err != nil {
		t.Fatal(err)
	}
	w := serve(s, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if got := w.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS over http: %q", got)
	}
	if w.Header().Get("Content-Security-Policy") != contentSecurityPolicy() || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers: %v", w.Header())
	}
}

func TestFormSources(t *testing.T) {
	got := formSources(
		"https://App.Example.com/callback?x=1",
		"https://app.example.com/other",
		"https://app.example.com:8443/cb",
		"http://127.0.0.1:53682/callback",
		"http://localhost/cb",
		"http://[::1]:9000/cb",
		"com.example.app:/oauth2redirect",
		"https://evil.example.com;script-src *",
		"https://a.example.com'/cb",
		"relative/path",
		"",
	)
	want := []string{
		"https://app.example.com",
		"https://app.example.com:8443",
		"http://127.0.0.1:*",
		"http://localhost:*",
		"http://[::1]:*",
		"com.example.app:",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("formSources = %q, want %q", got, want)
	}
}
