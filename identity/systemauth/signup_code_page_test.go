package systemauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubCodes treats "good-code" as usable (stored as GOODCODE) and any other
// code as unusable.
type stubCodes struct{}

func (stubCodes) SignupCodeUsable(_ context.Context, code string) (string, bool, error) {
	if code == "good-code" {
		return "GOODCODE", true, nil
	}
	return "", false, nil
}

// codeGate allows a sign-up only when the context carries GOODCODE.
type codeGate struct{ stubGate }

func (g *codeGate) AllowSignup(ctx context.Context, _ ExternalLogin) error {
	if SignupCodeFromContext(ctx) != "GOODCODE" {
		return ErrSignupNotInvited
	}
	return nil
}

func getPage(s *Server, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func TestSignupPageAndCodeCarriedToTheGate(t *testing.T) {
	f := newFakeGitHub(t)
	gate := &codeGate{}
	s, err := newGatedServer(t, f, NewMemoryPrincipalDirectory(), WithSignupGate(gate),
		WithSignupCodes(stubCodes{}, SignupPage{ReturnTo: "https://app.example.com/start"}))
	if err != nil {
		t.Fatal(err)
	}

	bad := getPage(s, SignupPath+"?code=old-code")
	if bad.Code != http.StatusOK || !strings.Contains(bad.Body.String(), DefaultSignupPage.InvalidNotice) {
		t.Fatalf("invalid code page: %d %s", bad.Code, bad.Body)
	}
	if findCookie(t, bad.Result(), signupCodeCookie) != nil {
		t.Error("an invalid code set the cookie")
	}
	if bad.Header().Get("Referrer-Policy") != "no-referrer" || bad.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers = %v", bad.Header())
	}

	good := getPage(s, SignupPath+"?code=good-code")
	body := good.Body.String()
	if good.Code != http.StatusOK || !strings.Contains(body, "/login/github?return_to=https%3A%2F%2Fapp.example.com%2Fstart") {
		t.Fatalf("valid code page: %d %s", good.Code, body)
	}
	codeCookie := findCookie(t, good.Result(), signupCodeCookie)
	if codeCookie == nil || codeCookie.Value != "GOODCODE" || !codeCookie.HttpOnly || !codeCookie.Secure {
		t.Fatalf("code cookie = %+v", codeCookie)
	}

	// Without the cookie the gate refuses; with it the account is created
	// and the cookie cleared.
	state, stateCookie := startLogin(t, s, "")
	if w := callback(s, state, stateCookie); w.Code != http.StatusForbidden {
		t.Fatalf("no code: %d %s", w.Code, w.Body)
	}
	state, stateCookie = startLogin(t, s, "")
	w := callback(s, state, stateCookie, codeCookie)
	if w.Code != http.StatusFound {
		t.Fatalf("with code: %d %s", w.Code, w.Body)
	}
	if c := findCookie(t, w.Result(), signupCodeCookie); c == nil || c.MaxAge >= 0 {
		t.Errorf("code cookie not cleared after sign-up: %+v", c)
	}
	if len(gate.signedUp) != 1 {
		t.Errorf("signed up = %v", gate.signedUp)
	}
}

func TestInviteCodeOnLoginStart(t *testing.T) {
	f := newFakeGitHub(t)
	s, err := newGatedServer(t, f, NewMemoryPrincipalDirectory(), WithSignupGate(&codeGate{}),
		WithSignupCodes(stubCodes{}, SignupPage{}))
	if err != nil {
		t.Fatal(err)
	}
	w := getPage(s, "/login/github?invite_code=good-code")
	if w.Code != http.StatusFound {
		t.Fatalf("start: %d", w.Code)
	}
	if c := findCookie(t, w.Result(), signupCodeCookie); c == nil || c.Value != "GOODCODE" {
		t.Errorf("code cookie = %+v", c)
	}
	w = getPage(s, "/login/github?invite_code=old-code")
	if c := findCookie(t, w.Result(), signupCodeCookie); c != nil {
		t.Errorf("an unusable code set the cookie: %+v", c)
	}
}

func TestSignupPageReturnToMustBeAllowed(t *testing.T) {
	f := newFakeGitHub(t)
	if _, err := newGatedServer(t, f, NewMemoryPrincipalDirectory(), WithSignupGate(&codeGate{}),
		WithSignupCodes(stubCodes{}, SignupPage{ReturnTo: "https://evil.example.net/"})); err == nil {
		t.Error("a return_to outside the allowed origins was accepted")
	}
}

func TestSignupPageIsRateLimited(t *testing.T) {
	f := newFakeGitHub(t)
	s, err := newGatedServer(t, f, NewMemoryPrincipalDirectory(), WithSignupGate(&codeGate{}),
		WithSignupCodes(stubCodes{}, SignupPage{}))
	if err != nil {
		t.Fatal(err)
	}
	limited := false
	for range 40 {
		if w := getPage(s, SignupPath+"?code=guess"); w.Code == http.StatusTooManyRequests {
			limited = w.Header().Get("Retry-After") != ""
			break
		}
	}
	if !limited {
		t.Error("guessing codes through the page was not rate-limited")
	}
}
