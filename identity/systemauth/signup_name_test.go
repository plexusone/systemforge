package systemauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/plexusone/omnimail/memsender"
)

// namedAccount is the account the directory holds for an address after email
// sign-in, or nil.
func namedAccount(t *testing.T, dir PrincipalDirectory, email string) *HumanPrincipal {
	t.Helper()
	p, err := dir.FindByExternalIdentity(context.Background(), emailLoginProvider, email)
	if err != nil {
		return nil
	}
	return p
}

// newAccountAtNameForm signs a new address in with a code and returns the
// response that sends the browser to the name form, with the server, the
// directory and the mail sender.
func newAccountAtNameForm(t *testing.T, email string) (*Server, PrincipalDirectory, *memsender.Sender, *httptest.ResponseRecorder) {
	t.Helper()
	dir := NewMemoryPrincipalDirectory()
	s, sender := newEmailLoginServer(t, nil, nil, dir)
	_, cookie := requestCode(t, s, email)
	w := submitCodeRaw(s, cookie, lastCode(t, sender))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != SignupNamePath {
		t.Fatalf("a new account was not sent to the name form: %d %q", w.Code, w.Header().Get("Location"))
	}
	return s, dir, sender, w
}

func nameCookieOf(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	c := findCookieIn(w.Result(), signupNameCookie)
	if c == nil || c.Value == "" {
		t.Fatal("no sign-up cookie")
	}
	return c
}

func postName(s *Server, c *http.Cookie, name, org string) *httptest.ResponseRecorder {
	return postIssuerForm(s, SignupNamePath, url.Values{
		"name": {name}, "organization_name": {org}, "csrf_token": {signupNameCSRF(c.Value)},
	}, c)
}

func TestNewAccountIsAskedForANameAndNotCreatedBeforeIt(t *testing.T) {
	s, dir, _, w := newAccountAtNameForm(t, "jane.doe@example.com")
	c := nameCookieOf(t, w)
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.MaxAge <= 0 {
		t.Errorf("sign-up cookie not hardened: %+v", c)
	}
	if findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Fatal("signed in before the name was given")
	}
	if namedAccount(t, dir, "jane.doe@example.com") != nil {
		t.Fatal("an account exists before the name was given")
	}

	page := getWithCookies(s, SignupNamePath, c)
	body := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(body, `name="name"`) || !strings.Contains(body, `name="organization_name"`) ||
		!strings.Contains(body, "we do not take it from your email address") {
		t.Fatalf("name form: %d %s", page.Code, body)
	}
	if strings.Contains(body, "jane.doe") {
		t.Error("the name form shows the address")
	}

	done := postName(s, c, "  Jane   Doe ", "")
	if done.Code != http.StatusFound || done.Header().Get("Location") != emailTestReturn {
		t.Fatalf("answering: %d %q: %s", done.Code, done.Header().Get("Location"), done.Body.String())
	}
	if findCookie(t, done.Result(), LoginCookieName) == nil {
		t.Fatal("no session after the name")
	}
	p := namedAccount(t, dir, "jane.doe@example.com")
	if p == nil || p.DisplayName != "Jane Doe" || !p.EmailVerified || p.Email != "jane.doe@example.com" {
		t.Fatalf("account = %+v, want display name Jane Doe, with the address verified", p)
	}
	if x := findCookieIn(done.Result(), signupNameCookie); x == nil || x.MaxAge >= 0 {
		t.Errorf("sign-up cookie not cleared: %+v", x)
	}
}

func TestSignupNameIsValidated(t *testing.T) {
	s, dir, _, w := newAccountAtNameForm(t, "a@example.com")
	c := nameCookieOf(t, w)
	for name, in := range map[string]struct{ name, org string }{
		"empty":                {"", ""},
		"blank":                {"   ", ""},
		"an email address":     {"jane@example.com", ""},
		"an @ anywhere":        {"Jane @ work", ""},
		"too long":             {strings.Repeat("a", 101), ""},
		"control characters":   {"Jane\x07Doe", ""},
		"a workspace address":  {"Jane Doe", "jane@example.com"},
		"a workspace too long": {"Jane Doe", strings.Repeat("a", 81)},
	} {
		t.Run(name, func(t *testing.T) {
			got := postName(s, c, in.name, in.org)
			if got.Code != http.StatusBadRequest || findCookie(t, got.Result(), LoginCookieName) != nil {
				t.Fatalf("answer %+v: %d, want 400 and no session", in, got.Code)
			}
			if !strings.Contains(got.Body.String(), `role="alert"`) {
				t.Errorf("no message: %s", got.Body.String())
			}
		})
	}
	if namedAccount(t, dir, "a@example.com") != nil {
		t.Fatal("a refused name created an account")
	}
	// A refused answer leaves the sign-up waiting: the same browser can try again.
	if got := postName(s, c, "Ada Lovelace", ""); got.Code != http.StatusFound {
		t.Fatalf("a valid name after refused ones: %d %s", got.Code, got.Body.String())
	}
}

func TestSignupNameWhitespaceIsNormalized(t *testing.T) {
	s, dir, _, w := newAccountAtNameForm(t, "a@example.com")
	if got := postName(s, nameCookieOf(t, w), " Ada\n  Lovelace\t", ""); got.Code != http.StatusFound {
		t.Fatalf("answer: %d %s", got.Code, got.Body.String())
	}
	if p := namedAccount(t, dir, "a@example.com"); p == nil || p.DisplayName != "Ada Lovelace" {
		t.Fatalf("account = %+v, want the whitespace made single spaces", p)
	}
}

func TestSignupNameKeepsWhatWasTypedWhenRefused(t *testing.T) {
	s, _, _, w := newAccountAtNameForm(t, "a@example.com")
	got := postName(s, nameCookieOf(t, w), "Ada Lovelace", "ada@example.com")
	if !strings.Contains(got.Body.String(), `value="Ada Lovelace"`) {
		t.Errorf("the name was not kept: %s", got.Body.String())
	}
}

func TestSignupNameIsUsedOnce(t *testing.T) {
	s, dir, _, w := newAccountAtNameForm(t, "a@example.com")
	c := nameCookieOf(t, w)
	if got := postName(s, c, "Ada Lovelace", ""); got.Code != http.StatusFound {
		t.Fatalf("first answer: %d", got.Code)
	}
	again := postName(s, c, "Someone Else", "")
	if again.Code != http.StatusBadRequest || findCookie(t, again.Result(), LoginCookieName) != nil {
		t.Fatalf("a second answer: %d, want 400 and no session", again.Code)
	}
	if p := namedAccount(t, dir, "a@example.com"); p == nil || p.DisplayName != "Ada Lovelace" {
		t.Fatalf("account = %+v, want the first name kept", p)
	}
}

func TestSignupNameConcurrentAnswersCreateOneAccount(t *testing.T) {
	s, dir, _, w := newAccountAtNameForm(t, "a@example.com")
	c := nameCookieOf(t, w)
	var (
		wg sync.WaitGroup
		mu sync.Mutex
		ok int
	)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := postName(s, c, "Ada Lovelace", ""); got.Code == http.StatusFound {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d concurrent answers signed in, want exactly 1", ok)
	}
	if namedAccount(t, dir, "a@example.com") == nil {
		t.Fatal("no account")
	}
}

func TestSignupNameFormRefusals(t *testing.T) {
	s, _, _, w := newAccountAtNameForm(t, "a@example.com")
	c := nameCookieOf(t, w)

	t.Run("no sign-up waiting", func(t *testing.T) {
		if got := getWithCookies(s, SignupNamePath); got.Code != http.StatusBadRequest {
			t.Fatalf("GET without a cookie: %d, want 400", got.Code)
		}
		if got := postIssuerForm(s, SignupNamePath, url.Values{"name": {"Ada"}, "csrf_token": {"x"}}); got.Code != http.StatusBadRequest {
			t.Fatalf("POST without a cookie: %d, want 400", got.Code)
		}
	})
	t.Run("another browser's cookie", func(t *testing.T) {
		other := &http.Cookie{Name: signupNameCookie, Value: "not-the-cookie", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}
		if got := getWithCookies(s, SignupNamePath, other); got.Code != http.StatusBadRequest {
			t.Fatalf("GET with a stray cookie: %d, want 400", got.Code)
		}
	})
	t.Run("wrong form token", func(t *testing.T) {
		got := postIssuerForm(s, SignupNamePath, url.Values{"name": {"Ada"}, "csrf_token": {"nope"}}, c)
		if got.Code != http.StatusForbidden || findCookie(t, got.Result(), LoginCookieName) != nil {
			t.Fatalf("wrong token: %d, want 403", got.Code)
		}
	})
	t.Run("cross-origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, SignupNamePath, strings.NewReader(url.Values{"name": {"Ada"}, "csrf_token": {signupNameCSRF(c.Value)}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://evil.example.com")
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("cross-origin: %d, want 403", rec.Code)
		}
	})
}

func TestExistingAccountIsNotAskedForAName(t *testing.T) {
	s, dir, sender, w := newAccountAtNameForm(t, "a@example.com")
	if got := postName(s, nameCookieOf(t, w), "Ada Lovelace", ""); got.Code != http.StatusFound {
		t.Fatalf("first sign-in: %d", got.Code)
	}
	_ = dir
	_, cookie := requestCode(t, s, "a@example.com")
	again := submitCodeRaw(s, cookie, lastCode(t, sender))
	if again.Code != http.StatusFound || again.Header().Get("Location") != emailTestReturn {
		t.Fatalf("second sign-in: %d %q, want straight to the app", again.Code, again.Header().Get("Location"))
	}
}

func TestSignupNameIsAskedAfterTheAgeQuestion(t *testing.T) {
	// A login that has not answered the age question is asked that first, and
	// only then for a name: neither question is asked of a refused person.
	base := NewMemoryPrincipalDirectory()
	dir := &ageCheckedDirectory{PrincipalDirectory: &nameCheckedDirectory{PrincipalDirectory: base}}
	login := ExternalLogin{Provider: emailLoginProvider, Subject: "a@example.com", Email: "a@example.com", EmailProven: true}

	if _, err := dir.CreateFromExternal(context.Background(), login); !errors.Is(err, errSignupAgeRequired) {
		t.Fatalf("without the age answered: %v, want the age question", err)
	}
	_, err := dir.CreateFromExternal(withAgeConfirmed(context.Background()), login)
	var need *nameRequiredError
	if !errors.As(err, &need) || need.login.Email != "a@example.com" {
		t.Fatalf("with the age answered: %v, want the name question carrying the login", err)
	}
	login.Name = "Ada Lovelace"
	if p, err := dir.CreateFromExternal(withAgeConfirmed(context.Background()), login); err != nil || p.DisplayName != "Ada Lovelace" {
		t.Fatalf("with both: %+v, %v", p, err)
	}
}

// A login that gives neither a name nor a handle is asked for a name.
func TestSocialSignInWithoutANameAsksForOne(t *testing.T) {
	f := newFakeGitHub(t)
	f.noName = true
	dir := NewMemoryPrincipalDirectory()
	s := newSocialTestServer(t, f, dir)

	state, stateCookie := startLogin(t, s, "")
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != SignupNamePath {
		t.Fatalf("callback: %d %q, want the name form", w.Code, w.Header().Get("Location"))
	}
	if _, err := dir.FindByExternalIdentity(context.Background(), "github", "4242"); err == nil {
		t.Fatal("an account exists before the name was given")
	}
	done := postName(s, nameCookieOf(t, w), "Octavia Cat", "")
	if done.Code != http.StatusFound || findCookie(t, done.Result(), LoginCookieName) == nil {
		t.Fatalf("answering: %d", done.Code)
	}
	p, err := dir.FindByExternalIdentity(context.Background(), "github", "4242")
	if err != nil || p.DisplayName != "Octavia Cat" {
		t.Fatalf("account = %+v, %v; want the name given, not the email or the handle", p, err)
	}
}

func TestSocialSignInWithANameIsNotAsked(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s := newSocialTestServer(t, f, dir)
	state, stateCookie := startLogin(t, s, "")
	if w := callback(s, state, stateCookie); w.Code != http.StatusFound {
		t.Fatalf("callback: %d, want straight to the app", w.Code)
	}
	if p, err := dir.FindByExternalIdentity(context.Background(), "github", "4242"); err != nil || p.DisplayName != "Octo Cat" {
		t.Fatalf("account = %+v, %v; want the name GitHub gave", p, err)
	}
}

func TestSignupNameWorksWithoutMail(t *testing.T) {
	// A deployment with GitHub only and no mail section still parks the
	// sign-up: the token store is built for it.
	f := newFakeGitHub(t)
	f.noName = true
	s := newSocialTestServer(t, f, NewMemoryPrincipalDirectory())
	if s.verificationTokens == nil {
		t.Fatal("no token store without mail")
	}
}

func TestDisplayNameIsNeverTheEmail(t *testing.T) {
	for _, l := range []ExternalLogin{
		{Provider: "email", Subject: "a@example.com", Email: "a@example.com"},
		{Provider: "google", Subject: "1", Email: "b@example.com"},
	} {
		if got := displayNameFor(l); strings.Contains(got, "@") || got == "" {
			t.Errorf("displayNameFor(%+v) = %q", l, got)
		}
	}
	if got := displayNameFor(ExternalLogin{Email: "a@example.com", Username: "octo"}); got != "octo" {
		t.Errorf("with a handle: %q, want the handle", got)
	}
}

func TestANameThatIsAnAddressIsNoName(t *testing.T) {
	// Some profiles carry the address in the name field. It is treated as no
	// name, so the person is asked, and it is never stored as the display name.
	base := NewMemoryPrincipalDirectory()
	dir := &nameCheckedDirectory{PrincipalDirectory: base}
	login := ExternalLogin{Provider: "google", Subject: "g1", Email: "jane@example.com", EmailVerified: true, Name: "jane@example.com"}
	_, err := dir.CreateFromExternal(context.Background(), login)
	var need *nameRequiredError
	if !errors.As(err, &need) {
		t.Fatalf("a name that is an address: %v, want the name question", err)
	}
	if got := displayNameFor(login); strings.Contains(got, "@") {
		t.Errorf("displayNameFor kept the address: %q", got)
	}
	login.Name = "Jane Doe"
	if p, err := dir.CreateFromExternal(context.Background(), login); err != nil || p.DisplayName != "Jane Doe" {
		t.Fatalf("with a real name: %+v, %v", p, err)
	}
}

func TestHumanDisplayNameIsNeverTheEmail(t *testing.T) {
	for _, h := range []*HumanPrincipal{
		{Email: "a@example.com"},
		{Email: "a@example.com", DisplayName: "a@example.com"},
		{Email: "a@example.com", DisplayName: "   "},
	} {
		if got := humanDisplayName(h); strings.Contains(got, "@") || got == "" {
			t.Errorf("humanDisplayName(%+v) = %q", h, got)
		}
	}
	if got := humanDisplayName(&HumanPrincipal{DisplayName: "Ada Lovelace"}); got != "Ada Lovelace" {
		t.Errorf("humanDisplayName kept a real name as %q", got)
	}
}

func TestNameClaimIsNeverAnAddress(t *testing.T) {
	// An account from before names were asked for may hold its address as its
	// name. Applications show the name claim to other people, so it is left
	// out; the address is still released as the email claim.
	dir := NewMemoryPrincipalDirectory()
	srv := newSocialTestServer(t, newFakeGitHub(t), dir)
	ctx := context.Background()
	for _, tc := range []struct{ email, name, want string }{
		{"old@example.com", "old@example.com", ""},
		{"new@example.com", "New Person", "New Person"},
	} {
		p, err := dir.CreateFromExternal(ctx, ExternalLogin{Provider: "github", Subject: tc.email, Email: tc.email, EmailVerified: true, Name: "Seed"})
		if err != nil {
			t.Fatalf("CreateFromExternal: %v", err)
		}
		dir.mu.Lock()
		dir.principals[p.ID].DisplayName = tc.name
		dir.mu.Unlock()
		claims := srv.sessionProvider.GetUserClaims(ctx, p.ID.String(), []string{"openid", "profile", "email"})
		got, released := claims["name"].(string)
		if got != tc.want || released != (tc.want != "") {
			t.Errorf("name claim for a stored name %q = %q (released %v), want %q", tc.name, got, released, tc.want)
		}
		if claims["email"] != tc.email {
			t.Errorf("email claim = %v, want %s", claims["email"], tc.email)
		}
	}
}
