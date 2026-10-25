package bff

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaultCookieIsHostPrefixed(t *testing.T) {
	m := NewCookieManager(CookieConfig{})
	cfg := m.Config()
	if !strings.HasPrefix(cfg.Name, "__Host-") {
		t.Fatalf("default cookie name = %q, want a __Host- prefix", cfg.Name)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}

	rr := httptest.NewRecorder()
	m.SetSessionCookie(rr, "id", time.Now().Add(time.Hour))
	c := rr.Result().Cookies()[0]
	if c.Domain != "" || c.Path != "/" || !c.Secure {
		t.Errorf("cookie Domain=%q Path=%q Secure=%v, want host-only, /, Secure", c.Domain, c.Path, c.Secure)
	}
}

func TestInsecureDevCookieDropsHostPrefix(t *testing.T) {
	cfg := NewCookieManager(CookieConfig{AllowInsecure: true}).Config()
	if cfg.Name != InsecureCookieName {
		t.Errorf("insecure default name = %q, want %q", cfg.Name, InsecureCookieName)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("insecure dev config invalid: %v", err)
	}
}

func TestCookieConfigValidate(t *testing.T) {
	bad := []CookieConfig{
		{Name: "__Host-x", Path: "/app", Secure: true},
		{Name: "__Host-x", Path: "/", Secure: false},
		{Name: "__Secure-x", Path: "/", Secure: false},
	}
	for _, c := range bad {
		if err := c.Validate(); !errors.Is(err, ErrInvalidCookieConfig) {
			t.Errorf("Validate(%+v) = %v, want ErrInvalidCookieConfig", c, err)
		}
	}
}

func TestNewHandler_RejectsHostCookieWithPath(t *testing.T) {
	_, err := NewHandler(HandlerConfig{
		Store:          NewMemoryStore(DefaultStoreConfig()),
		AllowedOrigins: []string{"https://example.com"},
		CookieConfig:   CookieConfig{Name: DefaultCookieName, Path: "/app"},
	})
	if !errors.Is(err, ErrInvalidCookieConfig) {
		t.Fatalf("NewHandler() error = %v, want ErrInvalidCookieConfig", err)
	}
}

// TestCustomNameCookieIsHostOnly expects a session cookie with a name
// other than the __Host- default to stay host-only, set and cleared
// without a Domain attribute.
func TestCustomNameCookieIsHostOnly(t *testing.T) {
	m := NewCookieManager(CookieConfig{Name: "app_session"})
	set := httptest.NewRecorder()
	m.SetSessionCookie(set, "id", time.Now().Add(time.Hour))
	cleared := httptest.NewRecorder()
	m.ClearSessionCookie(cleared)
	for _, rr := range []*httptest.ResponseRecorder{set, cleared} {
		h := rr.Header().Get("Set-Cookie")
		if strings.Contains(strings.ToLower(h), "domain=") {
			t.Errorf("Set-Cookie = %q, want no Domain attribute", h)
		}
	}
}
