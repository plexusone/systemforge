package systemauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// stubWaitlist records joins.
type stubWaitlist struct {
	mu    sync.Mutex
	joins []string
	last  [2]string // consent version and text of the last join
}

func (s *stubWaitlist) Join(_ context.Context, email, version, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.joins = append(s.joins, email)
	s.last = [2]string{version, text}
	return nil
}

func newWaitlistServer(t *testing.T, list SignupWaitlist, opts ...Option) *Server {
	t.Helper()
	s, err := newGatedServer(t, newFakeGitHub(t), NewMemoryPrincipalDirectory(),
		append([]Option{WithSignupWaitlist(list, WaitlistPage{Title: "Join Example"})}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWaitlistPage(t *testing.T) {
	s := newWaitlistServer(t, &stubWaitlist{})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, SignupWaitlistPath+"?error=invite_required", nil))
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Join Example") || !strings.Contains(body, DefaultWaitlistPage.RefusedNotice) ||
		!strings.Contains(body, DefaultWaitlistPage.ConsentText) {
		t.Fatalf("page: %d %s", w.Code, body)
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("headers: %v", w.Header())
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, SignupWaitlistPath, nil))
	if strings.Contains(w.Body.String(), DefaultWaitlistPage.RefusedNotice) {
		t.Error("refused notice shown without a refusal")
	}
}

func TestWaitlistJoin(t *testing.T) {
	list := &stubWaitlist{}
	s := newWaitlistServer(t, list)
	form := func(email, consent string) url.Values { return url.Values{"email": {email}, "consent": {consent}} }

	if w := postForm(s, SignupWaitlistPath, "https://evil.example.com", form("ada@example.com", "yes")); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin: %d", w.Code)
	}
	for name, f := range map[string]url.Values{
		"bad email":  form("not an email", "yes"),
		"name+addr":  form("Ada <ada@example.com>", "yes"),
		"no consent": form("ada@example.com", ""),
	} {
		if w := postForm(s, SignupWaitlistPath, testIssuer, f); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	if len(list.joins) != 0 {
		t.Fatalf("invalid submissions recorded: %v", list.joins)
	}
	w := postForm(s, SignupWaitlistPath, testIssuer, form("ada@example.com", "yes"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), DefaultWaitlistPage.Thanks) {
		t.Fatalf("join: %d %s", w.Code, w.Body)
	}
	if len(list.joins) != 1 || list.joins[0] != "ada@example.com" ||
		list.last != [2]string{DefaultWaitlistPage.ConsentVersion, DefaultWaitlistPage.ConsentText} {
		t.Fatalf("recorded %v %v", list.joins, list.last)
	}
}

func TestWaitlistEscapesInput(t *testing.T) {
	s := newWaitlistServer(t, &stubWaitlist{})
	w := postForm(s, SignupWaitlistPath, testIssuer, url.Values{"email": {`"><script>alert(1)</script>`}, "consent": {"yes"}})
	if strings.Contains(w.Body.String(), "<script>alert") {
		t.Fatalf("submitted input rendered unescaped: %s", w.Body)
	}
}

func TestWaitlistRateLimitsAnAddress(t *testing.T) {
	s := newWaitlistServer(t, &stubWaitlist{})
	form := url.Values{"email": {"ada@example.com"}, "consent": {"yes"}}
	for i := 0; i < DefaultWaitlistEmailLimit.Rate; i++ {
		if w := postForm(s, SignupWaitlistPath, testIssuer, form); w.Code != http.StatusOK {
			t.Fatalf("submission %d: %d", i+1, w.Code)
		}
	}
	w := postForm(s, SignupWaitlistPath, testIssuer, form)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("over the limit: %d %v", w.Code, w.Header())
	}
}

func TestRefusedSignupGoesToTheWaitlist(t *testing.T) {
	s := newWaitlistServer(t, &stubWaitlist{}, WithSignupGate(&stubGate{allowed: map[string]bool{}}))
	state, stateCookie := startLogin(t, s, "")
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != SignupWaitlistPath+"?error=invite_required" {
		t.Fatalf("refused sign-up: %d %q", w.Code, w.Header().Get("Location"))
	}
}

func TestWaitlistNotServedWithoutOne(t *testing.T) {
	s, err := newGatedServer(t, newFakeGitHub(t), NewMemoryPrincipalDirectory())
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, SignupWaitlistPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("waitlist served without one configured: %d", w.Code)
	}
}
