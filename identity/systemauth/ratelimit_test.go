package systemauth

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func rateLimitServer(t *testing.T, rl RateLimitConfig) *Server {
	t.Helper()
	s, err := NewEmbedded(Config{
		Issuer:    testIssuer,
		RateLimit: rl,
		Clients: []ClientConfig{{ID: "web", Type: "confidential", Name: "Web", Secret: "web-secret",
			GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"}, AllowBearerTokens: true}},
	})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

func limitedGet(s *Server, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = "192.0.2.1:1"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func limitedTokenRequest(s *Server, remote, secret string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth("web", secret)
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// TestRateLimitDefaultLayer verifies that every route is limited per
// client address with RateLimit headers, before any handler runs, and that
// health checks are exempt.
func TestRateLimitDefaultLayer(t *testing.T) {
	s := rateLimitServer(t, RateLimitConfig{Default: &RateLimitRule{Requests: 2, Period: Duration(time.Minute)}})
	for i := range 2 {
		w := limitedGet(s, "/.well-known/openid-configuration")
		if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("RateLimit-Policy"), `"default";q=2;w=60`) {
			t.Fatalf("request %d: %d %q", i, w.Code, w.Header().Get("RateLimit-Policy"))
		}
	}
	w := limitedGet(s, "/.well-known/openid-configuration")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || w.Header().Get("Retry-After") == "0" {
		t.Fatalf("over the limit: %d Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
	if w.Header().Get("X-Content-Type-Options") == "" {
		t.Error("a refused response lacks the security headers")
	}
	for range 3 {
		if w := limitedGet(s, HealthzPath); w.Code != http.StatusOK {
			t.Fatalf("health check limited: %d", w.Code)
		}
	}
}

// TestRateLimitTokenRoute verifies the token endpoint's route policy per
// address, configured by name.
func TestRateLimitTokenRoute(t *testing.T) {
	s := rateLimitServer(t, RateLimitConfig{Routes: []RateLimitRouteConfig{{
		Name: "token", Paths: []string{"/oauth/token"},
		PerAddress: &RateLimitRule{Requests: 1, Period: Duration(time.Minute)},
	}}})
	if w := limitedTokenRequest(s, "192.0.2.1:1", "web-secret"); w.Code != http.StatusOK {
		t.Fatalf("first token request: %d %s", w.Code, w.Body)
	}
	if w := limitedTokenRequest(s, "192.0.2.1:1", "web-secret"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second token request: %d", w.Code)
	}
	if w := limitedTokenRequest(s, "192.0.2.2:1", "web-secret"); w.Code != http.StatusOK {
		t.Fatalf("another address: %d", w.Code)
	}
}

// TestRateLimitDisabled verifies that rate_limit.disabled removes the
// layers.
func TestRateLimitDisabled(t *testing.T) {
	s := rateLimitServer(t, RateLimitConfig{Disabled: true, Default: &RateLimitRule{Requests: 1, Period: Duration(time.Minute)}})
	for range 3 {
		w := limitedGet(s, "/.well-known/openid-configuration")
		if w.Code != http.StatusOK || w.Header().Get("RateLimit") != "" {
			t.Fatalf("disabled layers: %d %q", w.Code, w.Header().Get("RateLimit"))
		}
	}
	if s.RateLimitPolicy() != nil {
		t.Error("RateLimitPolicy is set with the layers disabled")
	}
}

// TestRateLimitClientAuthFailures verifies that failed client
// authentication from one address and client is refused once its limit is
// used up, even with the right secret, while successes are not counted.
func TestRateLimitClientAuthFailures(t *testing.T) {
	s := rateLimitServer(t, RateLimitConfig{Disabled: true})
	for range 5 {
		if w := limitedTokenRequest(s, "192.0.2.1:1", "web-secret"); w.Code != http.StatusOK {
			t.Fatalf("good secret: %d", w.Code)
		}
	}
	for i := range DefaultClientAuthFailureLimit.Rate {
		if w := limitedTokenRequest(s, "192.0.2.1:1", "wrong"); w.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i, w.Code)
		}
	}
	w := limitedTokenRequest(s, "192.0.2.1:1", "web-secret")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("after the failures: %d", w.Code)
	}
	if w := limitedTokenRequest(s, "192.0.2.2:1", "web-secret"); w.Code != http.StatusOK {
		t.Fatalf("another address: %d", w.Code)
	}
}

func TestRateLimitConfigValidation(t *testing.T) {
	for name, rl := range map[string]RateLimitConfig{
		"zero default":    {Default: &RateLimitRule{}},
		"bad network":     {ExemptNetworks: []string{"nope"}},
		"bad route limit": {Routes: []RateLimitRouteConfig{{Name: "x", Paths: []string{"/x"}, PerAddress: &RateLimitRule{Requests: 1}}}},
		"route no paths":  {Routes: []RateLimitRouteConfig{{Name: "x"}}},
	} {
		if _, err := NewEmbedded(Config{Issuer: testIssuer, RateLimit: rl}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v, want ErrInvalidConfig", name, err)
		}
	}
}

func TestLimitRequest(t *testing.T) {
	s := rateLimitServer(t, RateLimitConfig{Disabled: true})
	limit := DefaultSocialLoginLimit
	limit.Rate, limit.Burst = 1, 1
	r := httptest.NewRequest(http.MethodGet, "/login/github", nil)
	r.RemoteAddr = "192.0.2.1:1"
	if !s.limitRequest(httptest.NewRecorder(), r, "social_login_start", limit) {
		t.Fatal("first request refused")
	}
	w := httptest.NewRecorder()
	if s.limitRequest(w, r, "social_login_start", limit) || w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: %d", w.Code)
	}
}

func TestUnverifiedSubject(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	if got := unverifiedSubject(enc(`{"alg":"none"}`) + "." + enc(`{"sub":"sa-1"}`) + ".sig"); got != "sa-1" {
		t.Errorf("subject = %q", got)
	}
	for _, bad := range []string{"", "a.b", "a.!!!.c", enc("{}") + "." + enc("not json") + ".c"} {
		if got := unverifiedSubject(bad); got != "" {
			t.Errorf("unverifiedSubject(%q) = %q", bad, got)
		}
	}
}
