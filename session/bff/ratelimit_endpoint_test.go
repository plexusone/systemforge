package bff

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func rateLimitedBFF(t *testing.T) http.Handler {
	t.Helper()
	h, err := NewHandler(HandlerConfig{
		Store:          NewMemoryStore(DefaultStoreConfig()),
		AllowedOrigins: []string{"https://example.com"},
		RateLimitConfig: &RateLimitConfig{
			RequestsPerMinute: 600,
			BurstSize:         100,
			EndpointLimits: map[string]EndpointLimit{
				"/logout": {RequestsPerMinute: 1, BurstSize: 2},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("closing handler: %v", err)
		}
	})
	root := chi.NewRouter()
	root.Mount("/bff", h.Router())
	return root
}

func countAllowed(h http.Handler, method, path string, n int) int {
	allowed := 0
	for range n {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Origin", "https://example.com")
		req.RemoteAddr = "192.0.2.10:1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusTooManyRequests {
			allowed++
		}
	}
	return allowed
}

// The stricter /logout limit must apply under a mount prefix, and even when
// the client's first request went to another path.
func TestRateLimiter_EndpointLimitAppliesUnderMountAfterOtherTraffic(t *testing.T) {
	h := rateLimitedBFF(t)

	if got := countAllowed(h, http.MethodGet, "/bff/session", 1); got != 1 {
		t.Fatalf("first /session request limited")
	}
	if got := countAllowed(h, http.MethodPost, "/bff/logout", 10); got != 2 {
		t.Errorf("/bff/logout allowed %d of 10 requests, want the endpoint burst of 2", got)
	}
	// The default bucket is separate and still has capacity.
	if got := countAllowed(h, http.MethodGet, "/bff/session", 5); got != 5 {
		t.Errorf("/bff/session allowed %d of 5 after /logout was limited", got)
	}
}

func TestRateLimiter_BasePath(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		BasePath:       "/bff",
		EndpointLimits: map[string]EndpointLimit{"/refresh": {RequestsPerMinute: 1, BurstSize: 1}},
		ExcludePaths:   []string{"/health"},
	})
	t.Cleanup(rl.Close)
	h := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	if got := countAllowed(h, http.MethodPost, "/bff/refresh", 3); got != 1 {
		t.Errorf("/bff/refresh allowed %d of 3, want 1", got)
	}
	if got := countAllowed(h, http.MethodGet, "/bff/health", 50); got != 50 {
		t.Errorf("/bff/health allowed %d of 50, want all (excluded)", got)
	}
}
