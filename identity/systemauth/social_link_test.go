package systemauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/oauthclient"
)

// linkStart posts the page's Link button for GitHub as the signed-in
// browser and returns the provider redirect's state and its cookie.
func linkStart(t *testing.T, s *Server, sess *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	return linkStartWith(t, s, sess, url.Values{})
}

// linkStartWith is linkStart posting form, such as the page's return_to.
func linkStartWith(t *testing.T, s *Server, sess *http.Cookie, form url.Values) (string, *http.Cookie) {
	t.Helper()
	w := postForm(s, SignInMethodsPath+"/github", testIssuer, form, sess)
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

	// The page, styled, shows the account and GitHub as linked; with every
	// provider linked, it offers none.
	req := httptest.NewRequest(http.MethodGet, SignInMethodsPath, nil)
	req.AddCookie(sess)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, pageStyleLink) ||
		!strings.Contains(body, "Signed in as <strong>octo@example.com</strong>") ||
		!strings.Contains(body, "<li>GitHub</li>") || strings.Contains(body, ">Link GitHub</button>") ||
		!strings.Contains(body, "Every available sign-in method is linked") {
		t.Fatalf("page: %d %s", w.Code, body)
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

// newTwoProviderServer is a social server with the fake GitHub and Google,
// whose authorization endpoint is never reached, and AcademyOS-like
// redirect settings.
func newTwoProviderServer(t *testing.T, f *fakeGitHub, dir PrincipalDirectory, signedOutName string) *Server {
	t.Helper()
	google := oauthclient.NewGoogleConnector(oauthclient.ProviderConfig{
		ClientID: "g-client", ClientSecret: "g-secret", RedirectURL: testIssuer + "/login/google/callback",
	})
	social := &SocialLoginConfig{AllowedRedirectOrigins: []string{"https://app.example.com"}}
	if signedOutName != "" {
		social.SignedOutURL, social.SignedOutName = "https://app.example.com/", signedOutName
	}
	s, err := NewEmbedded(Config{Issuer: testIssuer, SocialLogin: social},
		WithSocialConnector(f.connector()), WithSocialConnector(google), WithPrincipalDirectory(dir))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

func methodsPage(s *Server, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func TestSignInMethodsPage(t *testing.T) {
	const back = "https://app.example.com/settings"
	f := newFakeGitHub(t)
	s := newTwoProviderServer(t, f, NewMemoryPrincipalDirectory(), "")
	page := SignInMethodsPath + "?return_to=" + url.QueryEscape(back)

	// Signed out, the sign-in comes back to the page with its return_to.
	w := methodsPage(s, page)
	if want := LoginPath + "?return_to=" + url.QueryEscape(page); w.Code != http.StatusFound || w.Header().Get("Location") != want {
		t.Fatalf("signed out: %d %q, want %q", w.Code, w.Header().Get("Location"), want)
	}

	// Signed in with GitHub: GitHub is listed as linked, only Google is
	// offered, its form carries return_to, and the page links back.
	sess := socialSession(t, s)
	w = methodsPage(s, page, sess)
	body := w.Body.String()
	for _, want := range []string{
		"<li>GitHub</li>",
		">Link Google</button>",
		`<input type="hidden" name="return_to" value="https://app.example.com/settings">`,
		`<a href="https://app.example.com/settings">Back to app.example.com</a>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, ">Link GitHub</button>") {
		t.Errorf("page offers the linked GitHub:\n%s", body)
	}
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "https://accounts.google.com") {
		t.Errorf("form-action does not allow Google: %s", csp)
	}

	// A return_to outside the allowed origins is dropped, never linked.
	w = methodsPage(s, SignInMethodsPath+"?return_to="+url.QueryEscape("https://evil.example.com/x"), sess)
	if body := w.Body.String(); w.Code != http.StatusOK || strings.Contains(body, "evil.example.com") || strings.Contains(body, "Back to") {
		t.Errorf("invalid return_to: %d %s", w.Code, body)
	}

	// The site's name, when configured, names the back link.
	named := newTwoProviderServer(t, f, NewMemoryPrincipalDirectory(), "Example")
	if body := methodsPage(named, page, socialSession(t, named)).Body.String(); !strings.Contains(body, ">Back to Example</a>") {
		t.Errorf("named back link:\n%s", body)
	}
}

func TestLinkKeepsReturnTo(t *testing.T) {
	const back = "https://app.example.com/settings"
	f := newFakeGitHub(t)
	s := newTwoProviderServer(t, f, NewMemoryPrincipalDirectory(), "")
	sess := socialSession(t, s)

	// The link's outcome comes back to the page with return_to.
	f.userID, f.email = 5555, "other@example.com"
	state, stateCookie := linkStartWith(t, s, sess, url.Values{"return_to": {back}})
	w := callback(s, state, stateCookie, sess)
	want := SignInMethodsPath + "?linked=github&return_to=" + url.QueryEscape(back)
	if w.Code != http.StatusFound || w.Header().Get("Location") != want {
		t.Errorf("link: %d %q, want %q", w.Code, w.Header().Get("Location"), want)
	}

	// A refusal keeps it too.
	state, stateCookie = linkStartWith(t, s, sess, url.Values{"return_to": {back}})
	w = callback(s, state, stateCookie)
	if want := SignInMethodsPath + "?error=session&return_to=" + url.QueryEscape(back); w.Header().Get("Location") != want {
		t.Errorf("refused: %q, want %q", w.Header().Get("Location"), want)
	}

	// An invalid return_to is dropped at the start.
	f.userID, f.email = 6666, "third@example.com"
	state, stateCookie = linkStartWith(t, s, sess, url.Values{"return_to": {"https://evil.example.com/x"}})
	if w := callback(s, state, stateCookie, sess); w.Header().Get("Location") != SignInMethodsPath+"?linked=github" {
		t.Errorf("invalid return_to: %q", w.Header().Get("Location"))
	}

	// Without a session, the start sends the browser to sign in, keeping it.
	w = postForm(s, SignInMethodsPath+"/github", testIssuer, url.Values{"return_to": {back}})
	page := SignInMethodsPath + "?return_to=" + url.QueryEscape(back)
	if want := LoginPath + "?return_to=" + url.QueryEscape(page); w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
		t.Errorf("signed out start: %d %q, want %q", w.Code, w.Header().Get("Location"), want)
	}
}

func TestLinkedProviders(t *testing.T) {
	ctx := context.Background()
	dirs := map[string]func(t *testing.T) PrincipalDirectory{
		"memory":         func(*testing.T) PrincipalDirectory { return NewMemoryPrincipalDirectory() },
		"memory storage": func(*testing.T) PrincipalDirectory { return NewMemoryStorage().PrincipalDirectory() },
		"ent":            func(t *testing.T) PrincipalDirectory { return NewEntPrincipalDirectory(openTestEnt(t)) },
	}
	for name, newDir := range dirs {
		t.Run(name, func(t *testing.T) {
			dir := newDir(t)
			lister, ok := dir.(LinkedProviderLister)
			if !ok {
				t.Fatal("not a LinkedProviderLister")
			}
			p, err := dir.CreateFromExternal(ctx, githubLogin("1", "a@example.com", true))
			if err != nil {
				t.Fatal(err)
			}
			other, err := dir.CreateFromExternal(ctx, githubLogin("2", "b@example.com", true))
			if err != nil {
				t.Fatal(err)
			}
			for _, login := range []ExternalLogin{
				githubLogin("3", "a@example.com", true),
				{Provider: "google", Subject: "g1", Email: "a@example.com", EmailVerified: true},
			} {
				if err := dir.LinkExternalIdentity(ctx, p.ID, login); err != nil {
					t.Fatal(err)
				}
			}
			got, err := lister.LinkedProviders(ctx, p.ID)
			if err != nil || !slices.Equal(got, []string{"github", "google"}) {
				t.Errorf("linked to the account: %v %v", got, err)
			}
			if got, err := lister.LinkedProviders(ctx, other.ID); err != nil || !slices.Equal(got, []string{"github"}) {
				t.Errorf("linked to the other account: %v %v", got, err)
			}
		})
	}
}
