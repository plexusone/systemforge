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
		{Name: "__Host-x", Path: "/", Secure: true, Domain: "example.com"},
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

func TestNewHandler_RejectsHostCookieWithDomain(t *testing.T) {
	_, err := NewHandler(HandlerConfig{
		Store:          NewMemoryStore(DefaultStoreConfig()),
		AllowedOrigins: []string{"https://example.com"},
		CookieConfig:   CookieConfig{Name: DefaultCookieName, Domain: "example.com"},
	})
	if !errors.Is(err, ErrInvalidCookieConfig) {
		t.Fatalf("NewHandler() error = %v, want ErrInvalidCookieConfig", err)
	}
}
