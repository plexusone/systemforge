package systemauth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDecodeConfigSkipsDefaultsAndValidation(t *testing.T) {
	t.Setenv("TEST_DECODE_DSN", "file:decoded.db")
	for _, tc := range []struct {
		name   string
		data   string
		format ConfigFormat
	}{
		{"yaml", "database:\n  driver: sqlite\n  dsn: ${TEST_DECODE_DSN}\n", FormatYAML},
		{"json", `{"database":{"driver":"sqlite","dsn":"${TEST_DECODE_DSN}"}}`, FormatJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := DecodeConfig([]byte(tc.data), tc.format)
			if err != nil {
				t.Fatalf("DecodeConfig: %v", err)
			}
			if cfg.Issuer != "" || cfg.Tokens.AccessTokenLifetime != 0 {
				t.Errorf("defaults applied: issuer %q access %v", cfg.Issuer, cfg.Tokens.AccessTokenLifetime)
			}
			if cfg.Database == nil || cfg.Database.DSN != "file:decoded.db" {
				t.Errorf("env not expanded: %+v", cfg.Database)
			}
			if _, err := ParseConfig([]byte(tc.data), tc.format); !errors.Is(err, ErrMissingIssuer) {
				t.Errorf("ParseConfig without issuer: %v, want ErrMissingIssuer", err)
			}
		})
	}

	if _, err := DecodeConfig([]byte("x"), ConfigFormat("toml")); err == nil {
		t.Error("unsupported format accepted")
	}
	if _, err := DecodeConfig([]byte("{"), FormatJSON); err == nil {
		t.Error("malformed JSON accepted")
	}
}

func TestDecodeConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "systemauth.json")
	if err := os.WriteFile(path, []byte(`{"keys":{"key_id":"k1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := DecodeConfigFile(path)
	if err != nil {
		t.Fatalf("DecodeConfigFile: %v", err)
	}
	if cfg.Keys.KeyID != "k1" || cfg.Keys.Algorithm != "" {
		t.Errorf("decoded keys: %+v", cfg.Keys)
	}
	if _, err := LoadConfig(path); !errors.Is(err, ErrMissingIssuer) {
		t.Errorf("LoadConfig without issuer: %v, want ErrMissingIssuer", err)
	}
	if _, err := DecodeConfigFile(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file accepted")
	}
}

// TestAccessTokenLifetimeBounds verifies the ADR-010 default of 10 minutes
// and the 15 minute ceiling, for the deployment and for a client.
func TestAccessTokenLifetimeBounds(t *testing.T) {
	cfg := DefaultConfig("https://auth.example.com")
	if got := cfg.Tokens.AccessTokenLifetime.Duration(); got != 10*time.Minute {
		t.Errorf("default access token lifetime = %v, want 10m", got)
	}
	empty := &Config{Issuer: "https://auth.example.com"}
	empty.ApplyDefaults()
	if got := empty.Tokens.AccessTokenLifetime.Duration(); got != 10*time.Minute {
		t.Errorf("defaulted access token lifetime = %v, want 10m", got)
	}

	for lifetime, wantErr := range map[time.Duration]bool{
		time.Minute: false, 15 * time.Minute: false, 16 * time.Minute: true, time.Hour: true,
	} {
		c := DefaultConfig("https://auth.example.com")
		c.Tokens.AccessTokenLifetime = Duration(lifetime)
		err := c.Validate()
		if (err != nil) != wantErr || (err != nil && !errors.Is(err, ErrInvalidConfig)) {
			t.Errorf("Validate with %v = %v, want error %v", lifetime, err, wantErr)
		}
	}
	if _, err := ParseConfig([]byte("issuer: https://auth.example.com\ntokens:\n  access_token_lifetime: 1h\n"), FormatYAML); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("ParseConfig with a 1h lifetime = %v, want ErrInvalidConfig", err)
	}

	// A client's own lifetime is lowered to the ceiling.
	long := Duration(time.Hour)
	c, err := NewClientFromConfig(ClientConfig{ID: "app", Name: "App", Type: "public", AccessTokenLifetime: &long})
	if err != nil {
		t.Fatalf("NewClientFromConfig: %v", err)
	}
	if got := *c.AccessTokenLifetime; got != 15*time.Minute {
		t.Errorf("client lifetime = %v, want 15m", got)
	}
}
