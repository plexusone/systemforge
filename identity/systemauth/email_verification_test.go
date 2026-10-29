package systemauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/omnimail/memsender"
)

// newMailSocialTestServer is newSocialTestServer with verification mail
// delivered to a memory sender.
func newMailSocialTestServer(t *testing.T, f *fakeGitHub, dir PrincipalDirectory, mail *MailConfig, extra ...Option) (*Server, *memsender.Sender) {
	t.Helper()
	if mail == nil {
		mail = &MailConfig{Provider: MailProviderSES, From: "Example <no-reply@example.com>", ProductName: "Example"}
	}
	sender := memsender.New()
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		SocialLogin: &SocialLoginConfig{
			AllowedRedirectOrigins: []string{"https://app.example.com"},
			SkipConsent:            true,
		},
		Mail: mail,
	}, append([]Option{WithSocialConnector(f.connector()), WithPrincipalDirectory(dir), WithMailSender(sender)}, extra...)...)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s, sender
}

var linkToken = regexp.MustCompile(`token=([A-Za-z0-9_-]+)`)

// mailedToken returns the token of the last verification link sent.
func mailedToken(t *testing.T, sender *memsender.Sender) string {
	t.Helper()
	msg := sender.Last()
	if msg == nil {
		t.Fatal("no message sent")
	}
	m := linkToken.FindStringSubmatch(msg.Text)
	if m == nil {
		t.Fatalf("no link in message: %s", msg.Text)
	}
	return m[1]
}

// startPendingSignIn signs in with the unverified provider email and
// returns the pending sign-in's cookie.
func startPendingSignIn(t *testing.T, s *Server, returnTo string) *http.Cookie {
	t.Helper()
	state, stateCookie := startLogin(t, s, returnTo)
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != VerifyEmailPath {
		t.Fatalf("callback: status %d location %q: %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Fatal("session cookie set before the email was verified")
	}
	c := findCookie(t, w.Result(), verifyEmailCookie)
	if c == nil || c.Value == "" {
		t.Fatal("pending sign-in cookie not set")
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" || c.MaxAge <= 0 {
		t.Errorf("pending sign-in cookie not hardened: %+v", c)
	}
	return c
}

func getWithCookies(s *Server, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

// postForm posts form from the issuer's origin.
func postIssuerForm(s *Server, target string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", testIssuer)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func confirmVerify(s *Server, token string, cookie *http.Cookie) *httptest.ResponseRecorder {
	return postIssuerForm(s, VerifyEmailConfirmPath, url.Values{"token": {token}, "csrf_token": {verifyCSRF(cookie.Value)}}, cookie)
}

func unverifiedGitHub(t *testing.T) *fakeGitHub {
	f := newFakeGitHub(t)
	f.verified = false
	return f
}

func TestVerifyEmailCompletesSignIn(t *testing.T) {
	f := unverifiedGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s, sender := newMailSocialTestServer(t, f, dir, nil)

	pending := startPendingSignIn(t, s, "https://app.example.com/home")
	if sender.Len() != 1 || sender.Last().To[0].Email != f.email {
		t.Fatalf("verification mail: %d messages, last %+v", sender.Len(), sender.Last())
	}
	token := mailedToken(t, sender)
	if !strings.Contains(sender.Last().Text, testIssuer+VerifyEmailConfirmPath+"?token=") {
		t.Errorf("link does not point at the confirm page: %s", sender.Last().Text)
	}

	// The check-your-email page names the address and offers a resend.
	w := getWithCookies(s, VerifyEmailPath, pending)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), f.email) || !strings.Contains(w.Body.String(), VerifyEmailResendPath) {
		t.Fatalf("verify page: %d %s", w.Code, w.Body.String())
	}

	// Opening the link only shows a form: the token is not used yet.
	w = getWithCookies(s, VerifyEmailConfirmPath+"?token="+token, pending)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="token" value="`+token+`"`) {
		t.Fatalf("confirm page: %d %s", w.Code, w.Body.String())
	}
	if _, err := dir.FindByExternalIdentity(context.Background(), "github", "4242"); !errors.Is(err, ErrPrincipalNotFound) {
		t.Fatalf("opening the link signed in: %v", err)
	}

	w = confirmVerify(s, token, pending)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://app.example.com/home" {
		t.Fatalf("confirm: %d %q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if c := findCookie(t, w.Result(), LoginCookieName); c == nil || c.Value == "" {
		t.Fatal("no session after verification")
	}
	if c := findCookie(t, w.Result(), verifyEmailCookie); c == nil || c.MaxAge >= 0 {
		t.Error("pending sign-in cookie not cleared")
	}
	p, err := dir.FindByExternalIdentity(context.Background(), "github", "4242")
	if err != nil {
		t.Fatalf("identity not linked: %v", err)
	}
	if !p.EmailVerified || p.Email != f.email {
		t.Errorf("principal = %+v, want the verified address", p)
	}

	// The link works once.
	if w := confirmVerify(s, token, pending); w.Code != http.StatusBadRequest {
		t.Errorf("replayed link: status %d, want 400", w.Code)
	}
}

func TestVerifyEmailLinksExistingAccount(t *testing.T) {
	f := unverifiedGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	existing := HumanPrincipal{Email: f.email, EmailVerified: true, Active: true}
	if err := dir.AddPrincipal(existing); err != nil {
		t.Fatal(err)
	}
	owner, err := dir.FindByVerifiedEmail(context.Background(), f.email)
	if err != nil {
		t.Fatal(err)
	}
	s, sender := newMailSocialTestServer(t, f, dir, nil)

	pending := startPendingSignIn(t, s, "")
	if w := confirmVerify(s, mailedToken(t, sender), pending); w.Code != http.StatusFound {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
	p, err := dir.FindByExternalIdentity(context.Background(), "github", "4242")
	if err != nil || p.ID != owner.ID {
		t.Fatalf("identity linked to %v (%v), want the existing account %v", p, err, owner.ID)
	}
}

func TestVerifyEmailUnverifiedAccountConflict(t *testing.T) {
	f := unverifiedGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	if err := dir.AddPrincipal(HumanPrincipal{Email: f.email, EmailVerified: false, Active: true}); err != nil {
		t.Fatal(err)
	}
	s, sender := newMailSocialTestServer(t, f, dir, nil)
	pending := startPendingSignIn(t, s, "")
	if w := confirmVerify(s, mailedToken(t, sender), pending); w.Code != http.StatusConflict {
		t.Fatalf("confirm onto an account with an unverified email: %d, want 409", w.Code)
	}
}

func TestVerifyEmailBoundToBrowser(t *testing.T) {
	f := unverifiedGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s, sender := newMailSocialTestServer(t, f, dir, nil)

	victim := startPendingSignIn(t, s, "")
	token := mailedToken(t, sender)

	// Another browser with no pending sign-in sees only an explanation.
	if w := getWithCookies(s, VerifyEmailConfirmPath+"?token="+token); w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), token) {
		t.Fatalf("confirm page without the cookie: %d %s", w.Code, w.Body.String())
	}
	// A browser with a pending sign-in of its own cannot use the link.
	other := startPendingSignIn(t, s, "")
	if w := confirmVerify(s, token, other); w.Code != http.StatusBadRequest {
		t.Fatalf("link used by another pending sign-in: %d, want 400", w.Code)
	}
	if findCookie(t, confirmVerify(s, token, other).Result(), LoginCookieName) != nil {
		t.Fatal("session issued to another browser")
	}

	// Form checks: origin and CSRF token.
	req := httptest.NewRequest(http.MethodPost, VerifyEmailConfirmPath, strings.NewReader(url.Values{"token": {token}, "csrf_token": {verifyCSRF(victim.Value)}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example.com")
	req.AddCookie(victim)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin confirm: %d, want 403", w.Code)
	}
	if w := postIssuerForm(s, VerifyEmailConfirmPath, url.Values{"token": {token}, "csrf_token": {"forged"}}, victim); w.Code != http.StatusForbidden {
		t.Fatalf("forged CSRF token: %d, want 403", w.Code)
	}

	// None of that burned the victim's link.
	if w := confirmVerify(s, token, victim); w.Code != http.StatusFound {
		t.Fatalf("owner's confirm after failed attempts: %d %s", w.Code, w.Body.String())
	}
}

func TestVerifyEmailResend(t *testing.T) {
	f := unverifiedGitHub(t)
	mail := &MailConfig{Provider: MailProviderSES, From: "no-reply@example.com", PerAddress: &RateLimitRule{Requests: 2, Period: Duration(time.Hour)}}
	s, sender := newMailSocialTestServer(t, f, NewMemoryPrincipalDirectory(), mail)

	pending := startPendingSignIn(t, s, "")
	first := mailedToken(t, sender)
	resend := func() *httptest.ResponseRecorder {
		return postIssuerForm(s, VerifyEmailResendPath, url.Values{"csrf_token": {verifyCSRF(pending.Value)}}, pending)
	}
	w := resend()
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != VerifyEmailPath+"?resent=1" {
		t.Fatalf("resend: %d %q", w.Code, w.Header().Get("Location"))
	}
	if sender.Len() != 2 {
		t.Fatalf("messages = %d, want 2", sender.Len())
	}
	second := mailedToken(t, sender)

	// The address's limit is used up: the answer is the same, but nothing
	// is sent.
	w = resend()
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != VerifyEmailPath+"?resent=1" {
		t.Fatalf("limited resend: %d %q", w.Code, w.Header().Get("Location"))
	}
	if sender.Len() != 2 {
		t.Fatalf("limited resend sent mail: %d messages", sender.Len())
	}

	// Each resend replaces the earlier links.
	if w := confirmVerify(s, first, pending); w.Code != http.StatusBadRequest {
		t.Fatalf("replaced link: %d, want 400", w.Code)
	}
	if w := confirmVerify(s, second, pending); w.Code != http.StatusBadRequest {
		t.Fatalf("replaced link: %d, want 400", w.Code)
	}
	// Without the cookie there is nothing to resend.
	if w := getWithCookies(s, VerifyEmailPath); w.Code != http.StatusBadRequest {
		t.Fatalf("verify page without a pending sign-in: %d", w.Code)
	}
}

func TestVerifyEmailPerClientLimit(t *testing.T) {
	f := unverifiedGitHub(t)
	mail := &MailConfig{Provider: MailProviderSES, From: "no-reply@example.com", PerClient: &RateLimitRule{Requests: 1, Period: Duration(time.Hour)}}
	s, sender := newMailSocialTestServer(t, f, NewMemoryPrincipalDirectory(), mail)
	startPendingSignIn(t, s, "")
	state, stateCookie := startLogin(t, s, "")
	if w := callback(s, state, stateCookie); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second pending sign-in from the client: %d, want 429", w.Code)
	}
	if sender.Len() != 1 {
		t.Fatalf("messages = %d, want 1", sender.Len())
	}
}

func TestVerifyEmailDeliveryFailureLooksTheSame(t *testing.T) {
	f := unverifiedGitHub(t)
	s, sender := newMailSocialTestServer(t, f, NewMemoryPrincipalDirectory(), nil)
	sender.FailNext(errors.New("mailbox unavailable"))
	startPendingSignIn(t, s, "")
}

func TestUnverifiedEmailWithoutMailIsRefused(t *testing.T) {
	// Without mail the sign-in is refused, as before (see also
	// TestSocialLoginUnverifiedEmail); an address mail cannot be sent to is
	// refused even with mail.
	f := unverifiedGitHub(t)
	f.email = "not an address"
	s, sender := newMailSocialTestServer(t, f, NewMemoryPrincipalDirectory(), nil)
	state, stateCookie := startLogin(t, s, "")
	if w := callback(s, state, stateCookie); w.Code != http.StatusForbidden {
		t.Fatalf("unusable provider email: %d, want 403", w.Code)
	}
	if sender.Len() != 0 {
		t.Fatal("mail sent without an address")
	}
}

func TestVerifyEmailEnt(t *testing.T) {
	f := unverifiedGitHub(t)
	db := openTestEnt(t)
	owner := seedHuman(t, db, f.email, true)
	sender := memsender.New()
	s, err := NewEmbedded(Config{
		Issuer:      testIssuer,
		SocialLogin: &SocialLoginConfig{SkipConsent: true},
		Mail:        &MailConfig{Provider: MailProviderSES, From: "no-reply@example.com"},
	}, WithStorage(NewEntStorage(db)), WithSocialConnector(f.connector()), WithMailSender(sender))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if _, ok := s.verificationTokens.(*EntVerificationTokenStore); !ok {
		t.Fatalf("verification tokens in %T, want the database", s.verificationTokens)
	}
	pending := startPendingSignIn(t, s, "")
	if w := confirmVerify(s, mailedToken(t, sender), pending); w.Code != http.StatusFound {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
	p, err := s.social.directory.FindByExternalIdentity(context.Background(), "github", "4242")
	if err != nil || p.ID != owner {
		t.Fatalf("identity linked to %v (%v), want %v", p, err, owner)
	}
}

func TestResolveExternalLoginProvenEmail(t *testing.T) {
	ctx := context.Background()
	dir := NewMemoryPrincipalDirectory()
	if err := dir.AddPrincipal(HumanPrincipal{Email: "jane@example.com", EmailVerified: true, Active: true}); err != nil {
		t.Fatal(err)
	}
	// Unproven and unverified: refused.
	login := githubLogin("1", "jane@example.com", false)
	if _, err := ResolveExternalLogin(ctx, dir, login, time.Now()); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("unverified: %v", err)
	}
	// Proven: links to the account with that verified email.
	login.EmailProven = true
	p, err := ResolveExternalLogin(ctx, dir, login, time.Now())
	if err != nil || p.Email != "jane@example.com" {
		t.Fatalf("proven: %+v %v", p, err)
	}
	// Proven with no address proves nothing.
	empty := githubLogin("2", "", false)
	empty.EmailProven = true
	if _, err := ResolveExternalLogin(ctx, dir, empty, time.Now()); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("proven without an address: %v", err)
	}
}
