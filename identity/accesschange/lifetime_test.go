package accesschange_test

import (
	"testing"
	"time"

	"github.com/plexusone/systemforge/identity/accesschange"
)

func TestClampAccessTokenLifetime(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		0:                accesschange.DefaultAccessTokenLifetime,
		-time.Minute:     accesschange.DefaultAccessTokenLifetime,
		time.Minute:      time.Minute,
		15 * time.Minute: 15 * time.Minute,
		time.Hour:        accesschange.MaxAccessTokenLifetime,
	} {
		if got := accesschange.ClampAccessTokenLifetime(in); got != want {
			t.Errorf("Clamp(%v) = %v, want %v", in, got, want)
		}
	}
	if accesschange.DefaultAccessTokenLifetime != 10*time.Minute || accesschange.MaxAccessTokenLifetime != 15*time.Minute {
		t.Errorf("default %v, max %v; ADR-010 says 10m and 15m", accesschange.DefaultAccessTokenLifetime, accesschange.MaxAccessTokenLifetime)
	}
}
