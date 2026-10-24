package systemauthsvc_test

import (
	"testing"

	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// TestDPoPReplayCacheRedisURL verifies that the service connects the DPoP
// replay cache to the configured Redis, and refuses a malformed URL.
func TestDPoPReplayCacheRedisURL(t *testing.T) {
	cfg := &systemauthsvc.Config{Issuer: "https://auth.example.com"}
	cfg.DPoP.ReplayCacheRedisURL = "redis://127.0.0.1:6379/0"
	svc, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{Dev: true, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("New with a Redis replay cache: %v", err)
	}
	if err := svc.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	bad := &systemauthsvc.Config{Issuer: "https://auth.example.com"}
	bad.DPoP.ReplayCacheRedisURL = "mysql://not-redis"
	if _, err := systemauthsvc.New(t.Context(), bad, systemauthsvc.Options{Dev: true, Logger: discardLogger()}); err == nil {
		t.Error("a malformed replay cache URL was accepted")
	}
}
