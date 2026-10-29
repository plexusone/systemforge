package systemauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReachedAge(t *testing.T) {
	now := time.Date(2026, time.October, 22, 15, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		year  int
		month time.Month
		want  bool
	}{
		{2008, time.September, true}, // turned 18 by September 30
		{2008, time.October, false},  // may turn 18 as late as October 31
		{2008, time.November, false}, // still 17
		{1990, time.January, true},   // well over
		{2026, time.January, false},  // this year
		{2008, time.February, true},  // a leap year's February counts its 29th
		{2007, time.December, true},  // turned 18 last December
		{2009, time.January, false},  // 17
		{1908, time.October, true},   // the oldest answer offered
	} {
		if got := reachedAge(tc.year, tc.month, 18, now); got != tc.want {
			t.Errorf("reachedAge(%d %s) = %v, want %v", tc.year, tc.month, got, tc.want)
		}
	}
	// On the last day of the birth month the person has certainly reached it.
	if !reachedAge(2008, time.October, 18, time.Date(2026, time.October, 31, 0, 0, 0, 0, time.UTC)) {
		t.Error("not of age on the last day of the birth month")
	}
}

func newAgeServer(t *testing.T, f *fakeGitHub, dir PrincipalDirectory, opts ...Option) *Server {
	t.Helper()
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID: "spa", Type: "public", Name: "SPA",
			RedirectURIs:  []string{"https://app.example.com/callback"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email"},
		}},
		SocialLogin: &SocialLoginConfig{
			AllowedRedirectOrigins: []string{"https://app.example.com"},
			SignupMinimumAge:       18,
		},
	}, append([]Option{WithSocialConnector(f.connector()), WithPrincipalDirectory(dir)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// answerAge posts a birth month and year to the age question.
func answerAge(s *Server, month, year string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	form := url.Values{"month": {month}, "year": {year}}
	req := httptest.NewRequest(http.MethodPost, SignupAgePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", testIssuer)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

func getAgePage(s *Server, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, SignupAgePath, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

// askedAge runs a new login to the age question and returns its cookie.
func askedAge(t *testing.T, s *Server, returnTo string) *http.Cookie {
	t.Helper()
	state, stateCookie := startLogin(t, s, returnTo)
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != SignupAgePath {
		t.Fatalf("new login: %d %q, want 303 to the age question", w.Code, w.Header().Get("Location"))
	}
	if findCookie(t, w.Result(), LoginCookieName) != nil {
		t.Fatal("a session was issued before the age question was answered")
	}
	c := findCookie(t, w.Result(), signupAgePendingCookie)
	if c == nil || c.Value == "" {
		t.Fatal("no pending age question cookie")
	}
	return c
}

func TestSignupAgeAdultCreatesAccountAfterConfirming(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s := newAgeServer(t, f, dir)

	pending := askedAge(t, s, "https://app.example.com/home")
	if len(dir.principals) != 0 {
		t.Fatalf("principals = %d before the age was answered, want none", len(dir.principals))
	}
	page := getAgePage(s, pending)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), `name="year"`) ||
		!strings.Contains(page.Body.String(), "18 or older") {
		t.Fatalf("age page: %d %s", page.Code, page.Body.String())
	}
	if !strings.Contains(page.Body.String(), `<option value="`+strconv.Itoa(time.Now().Year())+`">`) {
		t.Error("the year list leaves out recent years, hinting at the answer")
	}

	w := answerAge(s, "3", "1990", pending)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("adult answer: %d %s", w.Code, w.Body.String())
	}
	if want := startURL("github", "https://app.example.com/home"); w.Header().Get("Location") != want {
		t.Errorf("redirect = %q, want %q", w.Header().Get("Location"), want)
	}
	confirmed := findCookie(t, w.Result(), signupAgeConfirmedCookie)
	if confirmed == nil || confirmed.Value == "" {
		t.Fatal("no confirmation cookie")
	}

	state, stateCookie := startLogin(t, s, "https://app.example.com/home")
	w = callback(s, state, stateCookie, confirmed)
	if w.Code != http.StatusFound || w.Header().Get("Location") != "https://app.example.com/home" {
		t.Fatalf("confirmed login: %d %q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	if findCookie(t, w.Result(), LoginCookieName) == nil {
		t.Error("no session after a confirmed sign-up")
	}
	if _, err := dir.FindByExternalIdentity(context.Background(), "github", "4242"); err != nil {
		t.Fatalf("account not created: %v", err)
	}

	// The account now exists, so later logins are not asked.
	state, stateCookie = startLogin(t, s, "")
	if w := callback(s, state, stateCookie); w.Code != http.StatusFound {
		t.Fatalf("existing account asked again: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestSignupAgeRefusesMinorAndKeepsNothing(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s := newAgeServer(t, f, dir)

	pending := askedAge(t, s, "")
	w := answerAge(s, "1", strconv.Itoa(time.Now().Year()-12), pending)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Nothing about you has been kept") {
		t.Fatalf("minor answer: %d %s", w.Code, w.Body.String())
	}
	refused := findCookie(t, w.Result(), signupAgeRefusedCookie)
	if refused == nil || refused.Value == "" {
		t.Fatal("no refusal cookie")
	}
	if findCookie(t, w.Result(), signupAgeConfirmedCookie) != nil {
		t.Error("a minor was given a confirmation")
	}
	if len(dir.principals) != 0 {
		t.Errorf("principals = %d after a refusal, want none", len(dir.principals))
	}

	// The same browser cannot answer again with another year.
	pending = askedAge(t, s, "")
	if w := answerAge(s, "1", "1990", pending, refused); w.Code != http.StatusForbidden {
		t.Errorf("retry after refusal: %d, want 403", w.Code)
	}
	if w := getAgePage(s, pending, refused); w.Code != http.StatusForbidden {
		t.Errorf("page after refusal: %d, want 403", w.Code)
	}
	if len(dir.principals) != 0 {
		t.Errorf("principals = %d after a retry, want none", len(dir.principals))
	}
}

func TestSignupAgePendingIsSingleUse(t *testing.T) {
	f := newFakeGitHub(t)
	s := newAgeServer(t, f, NewMemoryPrincipalDirectory())

	pending := askedAge(t, s, "")
	// An incomplete answer does not use the question up.
	if w := answerAge(s, "", "1990", pending); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Choose the month") {
		t.Fatalf("incomplete answer: %d %s", w.Code, w.Body.String())
	}
	if w := answerAge(s, "13", "1990", pending); w.Code != http.StatusBadRequest {
		t.Fatalf("month 13: %d", w.Code)
	}
	if w := answerAge(s, "3", "1990", pending); w.Code != http.StatusSeeOther {
		t.Fatalf("answer after a correction: %d %s", w.Code, w.Body.String())
	}
	if w := answerAge(s, "3", "1990", pending); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "expired") {
		t.Errorf("second answer: %d, want 400 expired", w.Code)
	}
	if w := answerAge(s, "3", "1990"); w.Code != http.StatusBadRequest {
		t.Errorf("answer with no question: %d, want 400", w.Code)
	}
}

func TestSignupAgeRejectsCrossOriginAnswer(t *testing.T) {
	f := newFakeGitHub(t)
	s := newAgeServer(t, f, NewMemoryPrincipalDirectory())
	pending := askedAge(t, s, "")

	form := url.Values{"month": {"3"}, "year": {"1990"}}
	req := httptest.NewRequest(http.MethodPost, SignupAgePath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example.net")
	req.AddCookie(pending)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-origin answer: %d, want 403", w.Code)
	}
}

func TestSignupAgeConfirmationIsSingleUseAndNotUpstreamState(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	s := newAgeServer(t, f, dir)

	pending := askedAge(t, s, "")
	confirmed := findCookie(t, answerAge(s, "3", "1990", pending).Result(), signupAgeConfirmedCookie)
	if confirmed == nil {
		t.Fatal("no confirmation cookie")
	}

	// A confirmation presented as upstream state is refused and consumed.
	stateAs := &http.Cookie{Name: loginStateCookieName, Value: confirmed.Value} //nolint:gosec // G124: a request cookie in a test; attributes are not sent
	if w := callback(s, confirmed.Value, stateAs); w.Code != http.StatusBadRequest {
		t.Fatalf("confirmation used as state: %d, want 400", w.Code)
	}
	state, stateCookie := startLogin(t, s, "")
	if w := callback(s, state, stateCookie, confirmed); w.Code != http.StatusSeeOther {
		t.Errorf("used confirmation: %d, want the age question again", w.Code)
	}
	if len(dir.principals) != 0 {
		t.Errorf("principals = %d, want none", len(dir.principals))
	}
}

func TestSignupAgeAskedOnlyOfInvitedLogins(t *testing.T) {
	f := newFakeGitHub(t)
	dir := NewMemoryPrincipalDirectory()
	gate := &stubGate{allowed: map[string]bool{}}
	s := newAgeServer(t, f, dir, WithSignupGate(gate))

	state, stateCookie := startLogin(t, s, "")
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "invitation only") {
		t.Fatalf("uninvited: %d %q, want the invitation refusal before any age question", w.Code, w.Body.String())
	}

	gate.allowed["octo@example.com"] = true
	pending := askedAge(t, s, "")
	confirmed := findCookie(t, answerAge(s, "3", "1990", pending).Result(), signupAgeConfirmedCookie)
	state, stateCookie = startLogin(t, s, "")
	if w := callback(s, state, stateCookie, confirmed); w.Code != http.StatusFound {
		t.Fatalf("invited, confirmed: %d %s", w.Code, w.Body.String())
	}
	if len(gate.signedUp) != 1 {
		t.Errorf("SignedUp = %v, want the invite used once, after the age was confirmed", gate.signedUp)
	}
}

func TestSignupMinimumAgeValidation(t *testing.T) {
	f := newFakeGitHub(t)
	for _, bad := range []int{-1, 121} {
		_, err := NewEmbedded(Config{
			Issuer:      testIssuer,
			SocialLogin: &SocialLoginConfig{SignupMinimumAge: bad},
		}, WithSocialConnector(f.connector()), WithPrincipalDirectory(NewMemoryPrincipalDirectory()))
		if !errors.Is(err, ErrInvalidSocialLoginConfig) {
			t.Errorf("SignupMinimumAge %d: err = %v, want ErrInvalidSocialLoginConfig", bad, err)
		}
	}
}

func TestSignupAgePageWording(t *testing.T) {
	f := newFakeGitHub(t)
	s := newAgeServer(t, f, NewMemoryPrincipalDirectory(), WithSignupAgePage(SignupAgePage{Title: "How old are you?"}))
	pending := askedAge(t, s, "")
	body := getAgePage(s, pending).Body.String()
	if !strings.Contains(body, "How old are you?") || !strings.Contains(body, "18 or older") {
		t.Errorf("custom title with default message: %s", body)
	}
}
