package systemauthsvc_test

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
	"github.com/plexusone/systemforge/session/middleware"
	"github.com/plexusone/systemforge/session/ratelimit"
)

const rateLimitWarning = "rate limit counters are kept per instance"

func rateLimitService(t *testing.T, rl systemauth.RateLimitConfig, opts systemauthsvc.Options) (*systemauthsvc.Service, string, error) {
	t.Helper()
	logs := &syncBuffer{}
	cfg := &systemauthsvc.Config{
		Issuer:    "https://auth.example.com",
		Database:  &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		Tokens:    systemauth.TokenConfig{HMACSecret: strings.Repeat("h", 32)},
		RateLimit: rl,
	}
	opts.SigningKey = testKey(t)
	opts.Migrate = true
	opts.DPoPReplayCache = middleware.NewMemoryReplayCache()
	opts.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	s, err := systemauthsvc.New(t.Context(), cfg, opts)
	if err == nil {
		closeService(t, s)
	}
	return s, logs.String(), err
}

// TestRateLimitStorageWarning verifies that in-memory counters are warned
// about in production unless one instance is declared or the storage is
// shared, and that startup is not refused.
func TestRateLimitStorageWarning(t *testing.T) {
	_, out, err := rateLimitService(t, systemauth.RateLimitConfig{}, systemauthsvc.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.Contains(out, rateLimitWarning) {
		t.Errorf("no warning about per-instance counters:\n%s", out)
	}

	_, out, err = rateLimitService(t, systemauth.RateLimitConfig{SingleInstance: true}, systemauthsvc.Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if strings.Contains(out, rateLimitWarning) {
		t.Errorf("warned although one instance is declared:\n%s", out)
	}

	shared := ratelimit.NewMemoryStorage()
	t.Cleanup(func() {
		if err := shared.Close(); err != nil {
			t.Error(err)
		}
	})
	s, out, err := rateLimitService(t, systemauth.RateLimitConfig{}, systemauthsvc.Options{RateLimitStorage: shared})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if strings.Contains(out, rateLimitWarning) {
		t.Errorf("warned although the storage is injected:\n%s", out)
	}
	if s.Server().RateLimitStorage() != ratelimit.Storage(shared) {
		t.Error("the injected storage is not the server's")
	}
}

func TestRateLimitRedisURLInvalid(t *testing.T) {
	if _, _, err := rateLimitService(t, systemauth.RateLimitConfig{RedisURL: "http://not-redis"}, systemauthsvc.Options{}); err == nil ||
		!strings.Contains(err.Error(), "rate_limit.redis_url") {
		t.Fatalf("New = %v, want a rate_limit.redis_url error", err)
	}
}
