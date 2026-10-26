package bff

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultCookieConfig(t *testing.T) {
	cfg := DefaultCookieConfig()

	if cfg.Name != DefaultCookieName {
		t.Errorf("Name = %s, want "+DefaultCookieName, cfg.Name)
	}
	if cfg.Path != "/" {
		t.Errorf("Path = %s, want /", cfg.Path)
	}
	if !cfg.Secure {
		t.Error("Secure = false, want true")
	}
	if !cfg.HTTPOnly {
		t.Error("HTTPOnly = false, want true")
	}
	if cfg.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want SameSiteStrictMode", cfg.SameSite)
	}
}

func TestNewCookieManager(t *testing.T) {
	mgr := NewCookieManager(CookieConfig{})

	// Should apply defaults
	if mgr.config.Name != DefaultCookieName {
		t.Errorf("Name = %s, want "+DefaultCookieName, mgr.config.Name)
	}
	if mgr.config.Path != "/" {
		t.Errorf("Path = %s, want /", mgr.config.Path)
	}
	if mgr.config.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want SameSiteStrictMode", mgr.config.SameSite)
	}
}

func TestNewCookieManager_CustomConfig(t *testing.T) {
	cfg := CookieConfig{
		Name:     "custom_session",
		Path:     "/api",
		Secure:   true,
		HTTPOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	mgr := NewCookieManager(cfg)

	if mgr.config.Name != "custom_session" {
		t.Errorf("Name = %s, want custom_session", mgr.config.Name)
	}
	if mgr.config.Path != "/api" {
		t.Errorf("Path = %s, want /api", mgr.config.Path)
	}
	if mgr.config.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want SameSiteLaxMode", mgr.config.SameSite)
	}
}

func TestCookieManager_SetSessionCookie(t *testing.T) {
	mgr := NewCookieManager(DefaultCookieConfig())
	sessionID := "test-session-id"
	expiry := time.Now().Add(time.Hour)

	rr := httptest.NewRecorder()
	mgr.SetSessionCookie(rr, sessionID, expiry)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != DefaultCookieName {
		t.Errorf("Cookie name = %s, want "+DefaultCookieName, cookie.Name)
	}
	if cookie.Value != sessionID {
		t.Errorf("Cookie value = %s, want %s", cookie.Value, sessionID)
	}
	if cookie.Path != "/" {
		t.Errorf("Cookie path = %s, want /", cookie.Path)
	}
	if !cookie.HttpOnly {
		t.Error("Cookie HttpOnly = false, want true")
	}
	if !cookie.Secure {
		t.Error("Cookie Secure = false, want true")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("Cookie SameSite = %v, want SameSiteStrictMode", cookie.SameSite)
	}
}

func TestCookieManager_GetSessionID(t *testing.T) {
	mgr := NewCookieManager(DefaultCookieConfig())
	sessionID := "test-session-id"

	req := httptest.NewRequest("GET", "/", nil)
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  DefaultCookieName,
		Value: sessionID,
	})

	result := mgr.GetSessionID(req)
	if result != sessionID {
		t.Errorf("GetSessionID() = %s, want %s", result, sessionID)
	}
}

func TestCookieManager_GetSessionID_NoCookie(t *testing.T) {
	mgr := NewCookieManager(DefaultCookieConfig())

	req := httptest.NewRequest("GET", "/", nil)

	result := mgr.GetSessionID(req)
	if result != "" {
		t.Errorf("GetSessionID() = %s, want empty string", result)
	}
}

func TestCookieManager_GetSessionID_WrongCookie(t *testing.T) {
	mgr := NewCookieManager(DefaultCookieConfig())

	req := httptest.NewRequest("GET", "/", nil)
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  "other_cookie",
		Value: "some-value",
	})

	result := mgr.GetSessionID(req)
	if result != "" {
		t.Errorf("GetSessionID() = %s, want empty string", result)
	}
}

func TestCookieManager_ClearSessionCookie(t *testing.T) {
	mgr := NewCookieManager(DefaultCookieConfig())

	rr := httptest.NewRecorder()
	mgr.ClearSessionCookie(rr)

	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}

	cookie := cookies[0]
	if cookie.Name != DefaultCookieName {
		t.Errorf("Cookie name = %s, want "+DefaultCookieName, cookie.Name)
	}
	if cookie.Value != "" {
		t.Errorf("Cookie value = %s, want empty", cookie.Value)
	}
	if cookie.MaxAge != -1 {
		t.Errorf("Cookie MaxAge = %d, want -1", cookie.MaxAge)
	}
}

func TestCookieManager_Config(t *testing.T) {
	cfg := CookieConfig{
		Name: "test",
	}
	mgr := NewCookieManager(cfg)

	result := mgr.Config()
	if result.Name != "test" {
		t.Errorf("Config().Name = %s, want test", result.Name)
	}
}

func TestCookieManager_CustomName(t *testing.T) {
	mgr := NewCookieManager(CookieConfig{
		Name: "my_app_session",
	})

	sessionID := "custom-session-id"

	// Set cookie
	rr := httptest.NewRecorder()
	mgr.SetSessionCookie(rr, sessionID, time.Now().Add(time.Hour))

	// Verify cookie name
	cookies := rr.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Expected 1 cookie, got %d", len(cookies))
	}
	if cookies[0].Name != "my_app_session" {
		t.Errorf("Cookie name = %s, want my_app_session", cookies[0].Name)
	}

	// Get cookie
	req := httptest.NewRequest("GET", "/", nil)
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  "my_app_session",
		Value: sessionID,
	})

	result := mgr.GetSessionID(req)
	if result != sessionID {
		t.Errorf("GetSessionID() = %s, want %s", result, sessionID)
	}
}

func TestCookieManager_IntegrationRoundTrip(t *testing.T) {
	mgr := NewCookieManager(DefaultCookieConfig())
	sessionID := "integration-test-session"
	expiry := time.Now().Add(time.Hour)

	// Set the cookie
	rr := httptest.NewRecorder()
	mgr.SetSessionCookie(rr, sessionID, expiry)

	// Create a new request with the cookie from the response
	req := httptest.NewRequest("GET", "/", nil)
	for _, cookie := range rr.Result().Cookies() {
		req.AddCookie(cookie)
	}

	// Get the session ID back
	result := mgr.GetSessionID(req)
	if result != sessionID {
		t.Errorf("Round-trip: got %s, want %s", result, sessionID)
	}
}

// TestCookieKeepsItsProtectionsWhenPartiallyConfigured verifies that a
// config naming only some fields cannot yield a script-readable or
// plaintext-HTTP session cookie by accident.
func TestCookieKeepsItsProtectionsWhenPartiallyConfigured(t *testing.T) {
	set := func(cfg CookieConfig) *http.Cookie {
		w := httptest.NewRecorder()
		NewCookieManager(cfg).SetSessionCookie(w, "sid", time.Now().Add(time.Hour))
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatalf("cookies = %v", cookies)
		}
		return cookies[0]
	}
	c := set(CookieConfig{Name: "app_session"})
	if !c.Secure || !c.HttpOnly || c.Domain != "" {
		t.Errorf("partial config gave Secure=%v HttpOnly=%v", c.Secure, c.HttpOnly)
	}
	// Local development can opt out of Secure, never out of HttpOnly.
	dev := set(CookieConfig{Name: "dev", AllowInsecure: true})
	if dev.Secure || !dev.HttpOnly {
		t.Errorf("AllowInsecure gave Secure=%v HttpOnly=%v", dev.Secure, dev.HttpOnly)
	}
}
