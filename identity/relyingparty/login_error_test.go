package relyingparty

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newLoginErrorHarness(t *testing.T, path string) *bffHarness {
	t.Helper()
	fake := newFakeSystemAuth(t)
	store := NewMemoryPrincipalStore()
	b, err := NewBFF(BFFConfig{Client: fake.client(t), Principals: store, Memberships: LocalMemberships(store), LoginErrorPath: path})
	if err != nil {
		t.Fatalf("NewBFF: %v", err)
	}
	return &bffHarness{t: t, fake: fake, store: store, bff: b}
}

// With LoginErrorPath a browser whose sign-in fails lands on the sign-in page
// with the error code; a request asking for JSON still gets JSON.
func TestBFFLoginErrorsRedirectToTheLoginPage(t *testing.T) {
	h := newLoginErrorHarness(t, "/login?from=bff")
	_, stateCookie := h.start("/bff/auth/login")

	redirected := func(name string, req *http.Request, code string) {
		t.Helper()
		w := h.do(req)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("%s: %d %s, want 303", name, w.Code, w.Body.String())
		}
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if loc.Path != "/login" || loc.Query().Get("error") != code || loc.Query().Get("from") != "bff" {
			t.Errorf("%s: Location = %s, want /login?error=%s keeping from=bff", name, loc, code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/bff/auth/callback?error=access_denied", nil)
	req.AddCookie(stateCookie)
	redirected("upstream denial", req, "LOGIN_FAILED")

	req = httptest.NewRequest(http.MethodGet, "/bff/auth/callback?code=x&state=other", nil)
	req.AddCookie(stateCookie)
	redirected("bad state", req, "INVALID_STATE")

	redirected("unknown provider", httptest.NewRequest(http.MethodGet, "/bff/auth/myspace", nil), "UNKNOWN_PROVIDER")
	redirected("bad return_to", httptest.NewRequest(http.MethodGet, "/bff/auth/login?return_to=https://evil.example/", nil), "INVALID_RETURN_TO")

	req = httptest.NewRequest(http.MethodGet, "/bff/auth/callback?error=access_denied", nil)
	req.Header.Set("Accept", "application/json")
	if w := h.do(req); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"LOGIN_FAILED"`) {
		t.Errorf("JSON request: %d %s, want 400 LOGIN_FAILED JSON", w.Code, w.Body.String())
	}
}

// The upstream's error text is never copied into the redirect.
func TestBFFLoginErrorDoesNotReflectUpstreamText(t *testing.T) {
	h := newLoginErrorHarness(t, "/login")
	w := h.do(httptest.NewRequest(http.MethodGet, "/bff/auth/callback?error="+url.QueryEscape("<script>x</script>"), nil))
	if loc := w.Header().Get("Location"); loc != "/login?error=LOGIN_FAILED" {
		t.Errorf("Location = %q", loc)
	}
}

// Without LoginErrorPath errors stay JSON, as before.
func TestBFFLoginErrorsStayJSONByDefault(t *testing.T) {
	h := newHarness(t)
	w := h.do(httptest.NewRequest(http.MethodGet, "/bff/auth/callback?error=access_denied", nil))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `"code":"LOGIN_FAILED"`) {
		t.Errorf("default: %d %s", w.Code, w.Body.String())
	}
}

func TestNewBFFRefusesAnOffsiteLoginErrorPath(t *testing.T) {
	fake := newFakeSystemAuth(t)
	store := NewMemoryPrincipalStore()
	for _, bad := range []string{"https://evil.example/login", "//evil.example/login"} {
		if _, err := NewBFF(BFFConfig{Client: fake.client(t), Principals: store, LoginErrorPath: bad}); err == nil {
			t.Errorf("LoginErrorPath %q was accepted", bad)
		}
	}
}
