package oauthclient

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setStateCookie(t *testing.T, m *StateManager) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := m.SetStateCookie(rec, "s1"); err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	return cookies[0]
}

// TestStateManagerZeroValueIsSecure expects a zero-value or hand-built
// StateManager to write a Secure, HttpOnly, SameSite=Lax, host-only
// __Host- cookie.
func TestStateManagerZeroValueIsSecure(t *testing.T) {
	for name, m := range map[string]*StateManager{
		"zero":         {},
		"hand-built":   {MaxAge: 60},
		"secure false": {Secure: false, SameSite: http.SameSiteDefaultMode},
		"constructor":  NewStateManager(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := m.Validate(); err != nil {
				t.Fatal(err)
			}
			c := setStateCookie(t, m)
			if c.Name != StateCookieName || !strings.HasPrefix(c.Name, "__Host-") {
				t.Errorf("name = %q, want %q", c.Name, StateCookieName)
			}
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
				t.Errorf("state cookie not hardened: %+v", c)
			}
			if c.MaxAge <= 0 {
				t.Errorf("MaxAge = %d, want a positive default", c.MaxAge)
			}
		})
	}
}

// TestStateManagerInsecureOptIn expects the explicit development mode to
// use the plain name without Secure and to warn once at construction.
func TestStateManagerInsecureOptIn(t *testing.T) {
	var logs bytes.Buffer
	m := NewStateManagerInsecure(slog.New(slog.NewTextHandler(&logs, nil)))
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "not Secure") {
		t.Errorf("no warning about the insecure state cookie:\n%s", logs.String())
	}
	c := setStateCookie(t, m)
	if c.Name != InsecureStateCookieName || c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("insecure state cookie = %+v", c)
	}
	if n := strings.Count(logs.String(), "level=WARN"); n != 1 {
		t.Errorf("warned %d times, want once at construction", n)
	}

	// A hand-built opt-in without a name also gets the plain name.
	c = setStateCookie(t, &StateManager{AllowInsecure: true})
	if c.Name != InsecureStateCookieName || c.Secure {
		t.Errorf("hand-built insecure state cookie = %+v", c)
	}
}

// TestStateManagerRefusesInvalidConfig expects SameSite other than Lax
// and prefixed names without Secure to be refused, with nothing written.
func TestStateManagerRefusesInvalidConfig(t *testing.T) {
	for name, m := range map[string]*StateManager{
		"samesite none":          {SameSite: http.SameSiteNoneMode},
		"samesite strict":        {SameSite: http.SameSiteStrictMode},
		"host prefix insecure":   {AllowInsecure: true, CookieName: StateCookieName},
		"secure prefix insecure": {AllowInsecure: true, CookieName: "__Secure-state"},
		"negative max age":       {MaxAge: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if err := m.Validate(); !errors.Is(err, ErrInvalidStateCookieConfig) {
				t.Fatalf("Validate = %v, want ErrInvalidStateCookieConfig", err)
			}
			rec := httptest.NewRecorder()
			if err := m.SetStateCookie(rec, "s1"); !errors.Is(err, ErrInvalidStateCookieConfig) {
				t.Fatalf("SetStateCookie = %v, want ErrInvalidStateCookieConfig", err)
			}
			if len(rec.Result().Cookies()) != 0 {
				t.Error("cookie written for an invalid configuration")
			}
			req := httptest.NewRequest(http.MethodGet, "/cb?state=s1", nil)
			req.AddCookie(&http.Cookie{Name: StateCookieName, Value: "s1"}) //nolint:gosec // G124: a request cookie in a test; attributes are not sent
			if m.ValidateState(httptest.NewRecorder(), req, "s1") {
				t.Error("state accepted with an invalid configuration")
			}
		})
	}

	// Secure with a __Host- name is fine even when AllowInsecure is set.
	if err := (&StateManager{AllowInsecure: true, Secure: true, CookieName: StateCookieName}).Validate(); err != nil {
		t.Errorf("secure __Host- cookie refused: %v", err)
	}
}
