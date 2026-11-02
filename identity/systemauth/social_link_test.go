package systemauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// linkStart posts the page's Link button for GitHub as the signed-in
// browser and returns the provider redirect's state and its cookie.
func linkStart(t *testing.T, s *Server, sess *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	w := postForm(s, SignInMethodsPath+"/github", testIssuer, url.Values{}, sess)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("link start: %d %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := loc.Query().Get("state")
	cookie := findCookie(t, w.Result(), loginStateCookieName)
	if state == "" || cookie == nil {
		t.Fatalf("link start: no state in %q", w.Header().Get("Location"))
	}
	return state, cookie
}

func TestLinkSignInMethod(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s := newSocialTestServer(t, f, dir)
	ctx := context.Background()

	// Signed out, the page sends the browser to sign in and back.
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, SignInMethodsPath, nil))
	if w.Code != http.StatusFound || w.Header().Get("Location") != LoginPath+"?return_to="+url.QueryEscape(SignInMethodsPath) {
		t.Fatalf("signed out: %d %q", w.Code, w.Header().Get("Location"))
	}

	// Sign in as GitHub user 4242: the account.
	sess := socialSession(t, s)
	account, err := dir.FindByExternalIdentity(ctx, "github", "4242")
	if err != nil {
		t.Fatal(err)
	}

	// The page offers each provider, styled, and lets its form reach the
	// provider through the POST's redirect.
	req := httptest.NewRequest(http.MethodGet, SignInMethodsPath, nil)
	req.AddCookie(sess)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), ">Link GitHub</button>") || !strings.Contains(w.Body.String(), pageStyleLink) {
		t.Fatalf("page: %d %s", w.Code, w.Body.String())
	}
	// The fake provider is on loopback, which form-action names by host.
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' http://127.0.0.1") {
		t.Errorf("form-action does not allow the provider: %s", csp)
	}

	// A cross-origin POST is refused.
	if w := postForm(s, SignInMethodsPath+"/github", "https://evil.example.com", url.Values{}, sess); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin link: %d", w.Code)
	}

	// Link a second GitHub identity, 5555, with another email: it joins the
	// account; no account is created and the account's email stays.
	f.userID, f.email = 5555, "other@example.com"
	state, stateCookie := linkStart(t, s, sess)
	w = callback(s, state, stateCookie, sess)
	if w.Code != http.StatusFound || w.Header().Get("Location") != SignInMethodsPath+"?linked=github" {
		t.Fatalf("link: %d %q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	linked, err := dir.FindByExternalIdentity(ctx, "github", "5555")
	if err != nil || linked.ID != account.ID || linked.Email != account.Email {
		t.Fatalf("linked identity: %+v %v; account %+v", linked, err, account)
	}

	// Linking it again is a success that changes nothing.
	state, stateCookie = linkStart(t, s, sess)
	if w := callback(s, state, stateCookie, sess); w.Header().Get("Location") != SignInMethodsPath+"?linked=github" {
		t.Errorf("relink: %q", w.Header().Get("Location"))
	}

	// Signing in with the linked identity signs in to the same account.
	sess2 := socialSession(t, s)
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(sess2)
	got, err := s.CurrentLoginSession(r2)
	if err != nil || got.PrincipalID != account.ID {
		t.Errorf("signing in with the linked identity: %+v %v", got, err)
	}
}

func TestLinkSignInMethodRefusals(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s := newSocialTestServer(t, f, dir)
	ctx := context.Background()

	// Two accounts: 4242 and 7777.
	sessA := socialSession(t, s)
	f.userID, f.email = 7777, "b@example.com"
	_ = socialSession(t, s) //nolint:errcheck // the second account only has to exist; its session is not used
	other, err := dir.FindByExternalIdentity(ctx, "github", "7777")
	if err != nil {
		t.Fatal(err)
	}

	// An identity on another account is never moved.
	state, stateCookie := linkStart(t, s, sessA)
	w := callback(s, state, stateCookie, sessA)
	if w.Header().Get("Location") != SignInMethodsPath+"?error=other_account" {
		t.Errorf("another account's identity: %q", w.Header().Get("Location"))
	}
	if still, err := dir.FindByExternalIdentity(ctx, "github", "7777"); err != nil || still.ID != other.ID {
		t.Errorf("the identity moved: %+v %v", still, err)
	}

	// A link finished without the session that started it is refused.
	f.userID, f.email = 8888, "c@example.com"
	state, stateCookie = linkStart(t, s, sessA)
	w = callback(s, state, stateCookie)
	if w.Header().Get("Location") != SignInMethodsPath+"?error=session" {
		t.Errorf("no session at the callback: %q", w.Header().Get("Location"))
	}
	if _, err := dir.FindByExternalIdentity(ctx, "github", "8888"); err == nil {
		t.Error("an identity was linked or created without the session")
	}

	// The page names the problem, and only known ones.
	req := httptest.NewRequest(http.MethodGet, SignInMethodsPath+"?error=other_account&linked=<b>x</b>", nil)
	req.AddCookie(sessA)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if body := rec.Body.String(); !strings.Contains(body, "already belongs to another account") || strings.Contains(body, "<b>x</b>") {
		t.Errorf("page messages: %s", body)
	}
}
