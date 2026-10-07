package systemauth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
