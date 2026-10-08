package bff

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestRateLimiter_Basic(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         5,
	})
	defer rl.Close()

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First 5 requests should succeed (burst)
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i+1, rec.Code)
		}

		// Check headers
		limit := rec.Header().Get("X-RateLimit-Limit")
		if limit != "60" {
			t.Errorf("X-RateLimit-Limit = %s, want 60", limit)
		}
	}

	// 6th request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Request 6: expected 429, got %d", rec.Code)
	}

	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("Expected Retry-After header")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         2,
	})
	defer rl.Close()

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust limit for IP 1
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// IP 2 should still be allowed
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.2:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Different IP should not be rate limited, got %d", rec.Code)
	}
}

func TestRateLimiter_EndpointSpecificLimits(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         10,
		EndpointLimits: map[string]EndpointLimit{
			"/refresh": {RequestsPerMinute: 10, BurstSize: 2},
		},
	})
	defer rl.Close()

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// /refresh should have stricter limits
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/refresh", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("/refresh request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 3rd request to /refresh should be limited
	req := httptest.NewRequest("POST", "/refresh", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("/refresh request 3: expected 429, got %d", rec.Code)
	}

	// Check that the limit header reflects the endpoint-specific limit
	limit := rec.Header().Get("X-RateLimit-Limit")
	if limit != "10" {
		t.Errorf("X-RateLimit-Limit = %s, want 10", limit)
	}
}

func TestRateLimiter_ExcludePaths(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         1,
		ExcludePaths:      []string{"/health"},
	})
	defer rl.Close()

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust rate limit on regular path
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/api", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// /health should always work (excluded)
	req := httptest.NewRequest("GET", "/health", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("/health should not be rate limited, got %d", rec.Code)
	}

	// Excluded paths should not have rate limit headers
	if rec.Header().Get("X-RateLimit-Limit") != "" {
		t.Error("Excluded paths should not have rate limit headers")
	}
}

func TestRateLimiter_TokenRefill(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 600, // 10 per second
		BurstSize:         1,
	})
	defer rl.Close()

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Use up the burst
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should be limited
	req = httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429, got %d", rec.Code)
	}

	// Wait for refill (100ms = 1 token at 10/sec)
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	req = httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("After refill: expected 200, got %d", rec.Code)
	}
}

func TestRateLimiter_CustomKeyFunc(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         1,
		KeyFunc: func(r *http.Request) string {
			return r.Header.Get("X-API-Key")
		},
	})
	defer rl.Close()

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Use up limit for API key 1
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-API-Key", "key-1")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// Different API key should work
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-API-Key", "key-2")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Different API key should not be rate limited, got %d", rec.Code)
	}
}

func TestRateLimiter_CloudflareIP(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         1,
		ClientIPConfig: ClientIPConfig{
			TrustCloudflare:    true,
			CloudflareIPRanges: []string{"172.16.0.0/12"},
		},
	})
	defer rl.Close()

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Use up limit for CF client IP
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "172.16.0.1:12345" // CF proxy
		req.Header.Set("CF-Connecting-IP", "203.0.113.50")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	// Same CF client IP should be limited
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "172.16.0.2:12345" // Different CF proxy
	req.Header.Set("CF-Connecting-IP", "203.0.113.50")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Same CF client IP should be rate limited, got %d", rec.Code)
	}
}

func TestRateLimiter_Headers(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         5,
	})
	defer rl.Close()

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Check all rate limit headers
	limit := rec.Header().Get("X-RateLimit-Limit")
	remaining := rec.Header().Get("X-RateLimit-Remaining")
	reset := rec.Header().Get("X-RateLimit-Reset")

	if limit != "60" {
		t.Errorf("X-RateLimit-Limit = %s, want 60", limit)
	}

	remainingInt, _ := strconv.Atoi(remaining)
	if remainingInt != 4 { // 5 burst - 1 used = 4
		t.Errorf("X-RateLimit-Remaining = %s, want 4", remaining)
	}

	if reset == "" {
		t.Error("X-RateLimit-Reset should be set")
	}
}

func TestRateLimiter_OnLimitExceeded(t *testing.T) {
	customCalled := false
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         1,
		OnLimitExceeded: func(w http.ResponseWriter, r *http.Request, info RateLimitInfo) {
			customCalled = true
			w.Header().Set("X-Custom-Header", "rate-limited")
			http.Error(w, "Custom rate limit message", http.StatusTooManyRequests)
		},
	})
	defer rl.Close()

	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust limit
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}

	if !customCalled {
		t.Error("OnLimitExceeded should have been called")
	}
}

func TestDefaultRateLimitConfig(t *testing.T) {
	config := DefaultRateLimitConfig()

	if config.RequestsPerMinute != 60 {
		t.Errorf("RequestsPerMinute = %d, want 60", config.RequestsPerMinute)
	}

	if config.BurstSize != 10 {
		t.Errorf("BurstSize = %d, want 10", config.BurstSize)
	}

	if config.CleanupInterval != time.Minute {
		t.Errorf("CleanupInterval = %v, want 1m", config.CleanupInterval)
	}
}
