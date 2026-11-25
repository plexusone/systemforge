package systemauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/omnimail/memsender"
)

const emailTestReturn = "https://app.example.com/home"

var mailedCode = regexp.MustCompile(`(?m)^(\d{6,10})$`)

// newEmailLoginServer is a server with email sign-in only: no social
// provider, mail delivered to a memory sender.
func newEmailLoginServer(t *testing.T, email *EmailLoginConfig, mail *MailConfig, dir PrincipalDirectory, extra ...Option) (*Server, *memsender.Sender) {
	t.Helper()
	if email == nil {
		email = &EmailLoginConfig{}
	}
	if mail == nil {
		mail = &MailConfig{Provider: MailProviderSES, From: "Example <no-reply@example.com>", ProductName: "Example"}
	}
	if dir == nil {
		dir = NewMemoryPrincipalDirectory()
	}
	sender := memsender.New()
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		SocialLogin: &SocialLoginConfig{
			AllowedRedirectOrigins: []string{"https://app.example.com"},
			SkipConsent:            true,
			Email:                  email,
		},
		Mail: mail,
	}, append([]Option{WithPrincipalDirectory(dir), WithMailSender(sender)}, extra...)...)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s, sender
}

// requestCode posts an address and returns the response and the pending
// sign-in cookie.
func requestCode(t *testing.T, s *Server, email string) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	w := postIssuerForm(s, EmailLoginPath, url.Values{"email": {email}, "return_to": {emailTestReturn}})
	return w, findCookie(t, w.Result(), emailCodeCookie)
}

func lastCode(t *testing.T, sender *memsender.Sender) string {
	t.Helper()
	msg := sender.Last()
	if msg == nil {
		t.Fatal("no message sent")
	}
	m := mailedCode.FindStringSubmatch(msg.Text)
	if m == nil {
		t.Fatalf("no code in message: %s", msg.Text)
	}
	return m[1]
}

func submitCode(s *Server, cookie *http.Cookie, code string) *httptest.ResponseRecorder {
	return postIssuerForm(s, EmailCodePath, url.Values{"code": {code}, "csrf_token": {emailCodeCSRF(cookie.Value)}}, cookie)
}

func wrongCode(code string) string {
	if code == "000000" {
		return "000001"
	}
	return "000000"
}

func TestEmailSignInCreatesAccountAndSession(t *testing.T) {
	dir := NewMemoryPrincipalDirectory()
	s, sender := newEmailLoginServer(t, nil, nil, dir)

	// The address form.
	w := getWithCookies(s, EmailLoginPath+"?return_to="+url.QueryEscape(emailTestReturn))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="email"`) {
		t.Fatalf("form: %d %s", w.Code, w.Body.String())
	}

	w, cookie := requestCode(t, s, "  Jane.Doe@Example.com ")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != EmailCodePath {
		t.Fatalf("request: %d location %q: %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if cookie == nil || cookie.Value == "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge <= 0 {
		t.Fatalf("pending cookie not hardened: %+v", cookie)
	}
	if sender.Len() != 1 || sender.Last().To[0].Email != "jane.doe@example.com" {
		t.Fatalf("mail: %d messages, last %+v", sender.Len(), sender.Last())
	}
	code := lastCode(t, sender)

	// The code page names the address and offers a new code.
	w = getWithCookies(s, EmailCodePath, cookie)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "jane.doe@example.com") || !strings.Contains(w.Body.String(), EmailCodeResendPath) {
		t.Fatalf("code page: %d %s", w.Code, w.Body.String())
	}
	if _, err := dir.FindByExternalIdentity(context.Background(), emailLoginProvider, "jane.doe@example.com"); err == nil {
		t.Fatal("an account exists before the code was entered")
	}

	// People type spaces and hyphens in a code.
	w = submitCode(s, cookie, code[:3]+" - "+code[3:])
	if w.Code != http.StatusFound || w.Header().Get("Location") != emailTestReturn {
		t.Fatalf("submit: %d location %q: %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	session := findCookie(t, w.Result(), LoginCookieName)
	if session == nil || session.Value == "" {
		t.Fatal("no session cookie after a correct code")
	}
	if c := findCookie(t, w.Result(), emailCodeCookie); c == nil || c.MaxAge >= 0 {
		t.Errorf("pending cookie not cleared: %+v", c)
	}
	p, err := dir.FindByExternalIdentity(context.Background(), emailLoginProvider, "jane.doe@example.com")
	if err != nil || p.Email != "jane.doe@example.com" || !p.Active {
		t.Fatalf("principal = %+v, %v", p, err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(session)
	if ls, err := s.CurrentLoginSession(req); err != nil || ls.PrincipalID != p.ID || ls.Provider != emailLoginProvider {
		t.Fatalf("session = %+v, %v", ls, err)
	}

	// The code works once.
	if w := submitCode(s, cookie, code); w.Code != http.StatusBadRequest || findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Fatalf("a used code was accepted again: %d", w.Code)
	}
}

func TestEmailSignInLinksToExistingAccount(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s2, sender2 := newEmailLoginServer(t, nil, nil, dir, WithSocialConnector(f.connector()))
	state, stateCookie := startLogin(t, s2, emailTestReturn)
	if w := callback(s2, state, stateCookie); w.Code != http.StatusFound {
		t.Fatalf("github sign-in: %d %s", w.Code, w.Body.String())
	}
	github, err := dir.FindByExternalIdentity(context.Background(), "github", "4242")
	if err != nil {
		t.Fatalf("github principal: %v", err)
	}

	_, cookie := requestCode(t, s2, f.email)
	if w := submitCode(s2, cookie, lastCode(t, sender2)); w.Code != http.StatusFound {
		t.Fatalf("email sign-in: %d %s", w.Code, w.Body.String())
	}
	byEmail, err := dir.FindByExternalIdentity(context.Background(), emailLoginProvider, strings.ToLower(f.email))
	if err != nil || byEmail.ID != github.ID {
		t.Fatalf("email identity = %+v, %v; want the GitHub account %s", byEmail, err, github.ID)
	}
}

func TestEmailSignInWrongCodesUseUpTheTries(t *testing.T) {
	s, sender := newEmailLoginServer(t, &EmailLoginConfig{MaxAttempts: 3}, nil, nil)
	_, cookie := requestCode(t, s, "a@example.com")
	code := lastCode(t, sender)

	for i := 1; i <= 3; i++ {
		w := submitCode(s, cookie, wrongCode(code))
		if w.Code != http.StatusBadRequest || findCookie(t, w.Result(), LoginCookieName) != nil {
			t.Fatalf("wrong code %d: %d", i, w.Code)
		}
	}
	// The right code no longer works: the tries are spent.
	w := submitCode(s, cookie, code)
	if w.Code != http.StatusBadRequest || findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Fatalf("the code worked after its tries were used: %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Sign in again") {
		t.Errorf("no way to start again: %s", w.Body.String())
	}
}

func TestEmailSignInTriesLeftAreShown(t *testing.T) {
	s, sender := newEmailLoginServer(t, &EmailLoginConfig{MaxAttempts: 3}, nil, nil)
	_, cookie := requestCode(t, s, "a@example.com")
	w := submitCode(s, cookie, wrongCode(lastCode(t, sender)))
	if !strings.Contains(w.Body.String(), "2 tries left") {
		t.Errorf("body = %s", w.Body.String())
	}
}

func TestEmailSignInMalformedEntriesCountAsTries(t *testing.T) {
	s, sender := newEmailLoginServer(t, &EmailLoginConfig{MaxAttempts: 3}, nil, nil)
	_, cookie := requestCode(t, s, "a@example.com")
	code := lastCode(t, sender)
	for _, bad := range []string{"", "abc", code + "1", code[:5]} {
		if w := submitCode(s, cookie, bad); w.Code != http.StatusBadRequest {
			t.Fatalf("entry %q: %d", bad, w.Code)
		}
	}
	if w := submitCode(s, cookie, code); findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Fatal("entries of the wrong shape did not count as tries")
	}
}

func TestEmailSignInCorrectCodeConcurrentlyUsedOnce(t *testing.T) {
	s, sender := newEmailLoginServer(t, nil, nil, nil)
	_, cookie := requestCode(t, s, "a@example.com")
	code := lastCode(t, sender)

	const n = 10
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		signedIn int
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := submitCode(s, cookie, code)
			if w.Code == http.StatusFound {
				mu.Lock()
				signedIn++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if signedIn != 1 {
		t.Fatalf("%d concurrent correct entries signed in, want exactly 1", signedIn)
	}
}

func TestEmailSignInCodeIsBoundToTheBrowser(t *testing.T) {
	s, sender := newEmailLoginServer(t, nil, nil, nil)
	_, cookie := requestCode(t, s, "a@example.com")
	code := lastCode(t, sender)

	// Another browser has its own pending sign-in and cannot use this code.
	_, other := requestCode(t, s, "b@example.com")
	if w := submitCode(s, other, code); findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Fatal("a code worked in another browser's sign-in")
	}
	// A browser without the cookie cannot use it either.
	w := postIssuerForm(s, EmailCodePath, url.Values{"code": {code}, "csrf_token": {emailCodeCSRF(cookie.Value)}})
	if findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Fatal("a code worked without the browser's cookie")
	}
	// The owner still can.
	if w := submitCode(s, cookie, code); w.Code != http.StatusFound {
		t.Fatalf("the owner could not use the code: %d", w.Code)
	}
}

func TestEmailSignInStoresNoCode(t *testing.T) {
	s, sender := newEmailLoginServer(t, nil, nil, nil)
	_, cookie := requestCode(t, s, "a@example.com")
	code := lastCode(t, sender)
	tok, err := s.verificationTokens.Latest(context.Background(), PurposeSignInCode, emailCodeBinding(cookie.Value))
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if strings.Contains(string(tok.Data), code) || strings.Contains(tok.Binding, cookie.Value) {
		t.Fatalf("the stored token holds the code or the cookie: %s %s", tok.Data, tok.Binding)
	}
	// The hash is keyed: the same code under another key differs.
	if emailCodeMAC([]byte("another key"), tok.Binding, tok.Email, code) == emailCodeMAC(s.codeKey, tok.Binding, tok.Email, code) {
		t.Fatal("the code hash does not depend on the key")
	}
}

func TestEmailSignInDoesNotRevealAccounts(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s, _ := newEmailLoginServer(t, nil, nil, dir, WithSocialConnector(f.connector()))
	state, stateCookie := startLogin(t, s, emailTestReturn)
	if w := callback(s, state, stateCookie); w.Code != http.StatusFound {
		t.Fatalf("github sign-in: %d", w.Code)
	}
	known, unknown := f.email, "nobody@example.com"

	wk, _ := requestCode(t, s, known)
	wu, _ := requestCode(t, s, unknown)
	if wk.Code != wu.Code || wk.Header().Get("Location") != wu.Header().Get("Location") {
		t.Fatalf("known %d %q, unknown %d %q", wk.Code, wk.Header().Get("Location"), wu.Code, wu.Header().Get("Location"))
	}
}

func TestEmailSignInSuppressedSendLeavesNoLiveCode(t *testing.T) {
	mail := &MailConfig{
		Provider: MailProviderSES, From: "Example <no-reply@example.com>",
		PerAddress: &RateLimitRule{Requests: 1, Period: Duration(time.Hour)},
	}
	s, sender := newEmailLoginServer(t, nil, mail, nil)

	_, first := requestCode(t, s, "a@example.com")
	code := lastCode(t, sender)
	w, second := requestCode(t, s, "a@example.com")
	if sender.Len() != 1 {
		t.Fatalf("%d messages sent, want the second suppressed", sender.Len())
	}
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != EmailCodePath || second == nil {
		t.Fatalf("a suppressed request answered differently: %d %q", w.Code, w.Header().Get("Location"))
	}
	// The suppressed request's code is a decoy no one holds: even the code
	// mailed for the first request does not work in it.
	if w := submitCode(s, second, code); findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Fatal("a suppressed request left a live code")
	}
	// Nothing a guesser can enter matches the suppressed request's code,
	// while exactly one entry matches the mailed one.
	matches := func(cookie *http.Cookie) int {
		tok, err := s.verificationTokens.Latest(context.Background(), PurposeSignInCode, emailCodeBinding(cookie.Value))
		if err != nil {
			t.Fatalf("Latest: %v", err)
		}
		var payload emailCodePayload
		if err := json.Unmarshal(tok.Data, &payload); err != nil {
			t.Fatalf("payload: %v", err)
		}
		n := 0
		for i := range 1_000_000 {
			if emailCodeMAC(s.codeKey, tok.Binding, tok.Email, fmt.Sprintf("%06d", i)) == payload.MAC {
				n++
			}
		}
		return n
	}
	if n := matches(second); n != 0 {
		t.Fatalf("%d entries match a suppressed request's code, want none", n)
	}
	if n := matches(first); n != 1 {
		t.Fatalf("%d entries match the mailed code, want exactly 1", n)
	}
	// The first browser's code is unaffected.
	if w := submitCode(s, first, code); w.Code != http.StatusFound {
		t.Fatalf("the mailed code was refused: %d", w.Code)
	}
}

func TestEmailSignInNewCodeReplacesTheOld(t *testing.T) {
	s, sender := newEmailLoginServer(t, nil, nil, nil)
	_, cookie := requestCode(t, s, "a@example.com")
	old := lastCode(t, sender)

	w := postIssuerForm(s, EmailCodeResendPath, url.Values{"csrf_token": {emailCodeCSRF(cookie.Value)}}, cookie)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), EmailCodePath) {
		t.Fatalf("resend: %d %q", w.Code, w.Header().Get("Location"))
	}
	if sender.Len() != 2 {
		t.Fatalf("%d messages, want 2", sender.Len())
	}
	fresh := lastCode(t, sender)
	if fresh != old {
		if w := submitCode(s, cookie, old); findCookie(t, w.Result(), LoginCookieName) != nil {
			t.Fatal("the replaced code still worked")
		}
	}
	if w := submitCode(s, cookie, fresh); w.Code != http.StatusFound {
		t.Fatalf("the new code was refused: %d", w.Code)
	}
}

func TestEmailSignInCodeExpires(t *testing.T) {
	s, sender := newEmailLoginServer(t, &EmailLoginConfig{CodeLifetime: Duration(5 * time.Minute)}, nil, nil)
	s.social.now = func() time.Time { return time.Now().Add(-time.Hour) }
	_, cookie := requestCode(t, s, "a@example.com") // issued an hour ago
	s.social.now = time.Now
	if w := submitCode(s, cookie, lastCode(t, sender)); findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Fatal("an expired code worked")
	}
}

func TestEmailSignInRefusals(t *testing.T) {
	s, sender := newEmailLoginServer(t, nil, nil, nil)
	_, cookie := requestCode(t, s, "a@example.com")
	code := lastCode(t, sender)

	t.Run("cross-origin request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, EmailLoginPath, strings.NewReader(url.Values{"email": {"a@example.com"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://evil.example.com")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("code %d, want 403", w.Code)
		}
	})
	t.Run("cross-origin code", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, EmailCodePath, strings.NewReader(url.Values{"code": {code}, "csrf_token": {emailCodeCSRF(cookie.Value)}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://evil.example.com")
		req.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || findCookie(t, w.Result(), LoginCookieName) != nil {
			t.Fatalf("code %d, want 403 and no session", w.Code)
		}
	})
	t.Run("wrong form token", func(t *testing.T) {
		w := postIssuerForm(s, EmailCodePath, url.Values{"code": {code}, "csrf_token": {"nope"}}, cookie)
		if w.Code != http.StatusForbidden || findCookie(t, w.Result(), LoginCookieName) != nil {
			t.Fatalf("code %d, want 403 and no session", w.Code)
		}
	})
	t.Run("invalid address", func(t *testing.T) {
		for _, bad := range []string{"", "not-an-address", "a@", strings.Repeat("a", 300) + "@example.com"} {
			w, c := requestCode(t, s, bad)
			if w.Code != http.StatusBadRequest || c != nil {
				t.Errorf("address %q: %d, cookie %v", bad, w.Code, c)
			}
		}
	})
	t.Run("return_to outside the allowlist", func(t *testing.T) {
		w := postIssuerForm(s, EmailLoginPath, url.Values{"email": {"a@example.com"}, "return_to": {"https://evil.example.com/"}})
		if w.Code != http.StatusBadRequest {
			t.Fatalf("code %d, want 400", w.Code)
		}
		if w := getWithCookies(s, EmailLoginPath+"?return_to="+url.QueryEscape("https://evil.example.com/")); w.Code != http.StatusBadRequest {
			t.Fatalf("form code %d, want 400", w.Code)
		}
	})
	t.Run("no pending sign-in", func(t *testing.T) {
		if w := getWithCookies(s, EmailCodePath); w.Code != http.StatusBadRequest {
			t.Fatalf("code %d, want 400", w.Code)
		}
	})
}

func TestEmailSignInChooserOffersEmail(t *testing.T) {
	s, _ := newEmailLoginServer(t, nil, nil, nil)
	w := getWithCookies(s, LoginPath+"?return_to="+url.QueryEscape(emailTestReturn))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), EmailLoginPath+"?return_to=") {
		t.Fatalf("chooser: %d %s", w.Code, w.Body.String())
	}
}

func TestEmailSignInOffWithoutSection(t *testing.T) {
	f := newFakeGitHub(t)
	s, _ := newMailSocialTestServer(t, f, NewMemoryPrincipalDirectory(), nil)
	// "email" is not a provider, so /login/email is not a sign-in.
	if w := getWithCookies(s, EmailLoginPath); w.Code != http.StatusNotFound {
		t.Fatalf("code %d, want 404", w.Code)
	}
}

func TestEmailSignInRefusesAProviderNamedEmail(t *testing.T) {
	f := newFakeGitHub(t)
	c := f.connector()
	c.Provider = emailLoginProvider
	_, err := NewEmbedded(Config{
		Issuer:      testIssuer,
		SocialLogin: &SocialLoginConfig{Email: &EmailLoginConfig{}},
		Mail:        &MailConfig{Provider: MailProviderSES, From: "Example <no-reply@example.com>"},
	}, WithSocialConnector(c), WithMailSender(memsender.New()), WithPrincipalDirectory(NewMemoryPrincipalDirectory()))
	if err == nil {
		t.Fatal("a provider named email was accepted")
	}
}

func TestEmailCodeGeneration(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c, err := newEmailCode(6)
		if err != nil || len(c) != 6 {
			t.Fatalf("code %q, %v", c, err)
		}
		if _, ok := cleanEmailCode(c, 6); !ok {
			t.Fatalf("code %q is not 6 digits", c)
		}
		seen[c] = true
	}
	if len(seen) < 150 {
		t.Fatalf("only %d distinct codes in 200 draws", len(seen))
	}
	if c, err := newEmailCode(10); err != nil || len(c) != 10 {
		t.Fatalf("10-digit code %q, %v", c, err)
	}
}
