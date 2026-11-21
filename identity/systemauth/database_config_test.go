package systemauth

import (
	"errors"
	"testing"
)

func TestDatabaseMaxOpenConns(t *testing.T) {
	cfg := DefaultConfig(testIssuer)
	cfg.Database = &DatabaseConfig{Driver: "postgres", DSN: "postgres://x"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unset: %v", err)
	}
	if got := cfg.Database.OpenConns(); got != DefaultMaxOpenConns {
		t.Errorf("unset: OpenConns = %d, want %d", got, DefaultMaxOpenConns)
	}

	cfg.Database.MaxOpenConns = 10
	if err := cfg.Validate(); err != nil {
		t.Fatalf("10: %v", err)
	}
	if got := cfg.Database.OpenConns(); got != 10 {
		t.Errorf("10: OpenConns = %d", got)
	}

	cfg.Database.MaxOpenConns = -1
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("-1: Validate = %v, want ErrInvalidConfig", err)
	}
}

func TestDatabaseMaxOpenConnsFromYAML(t *testing.T) {
	cfg, err := ParseConfig([]byte("issuer: "+testIssuer+"\ndatabase:\n  driver: postgres\n  dsn: postgres://x\n  max_open_conns: 10\n"), FormatYAML)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.MaxOpenConns != 10 {
		t.Errorf("max_open_conns = %d, want 10", cfg.Database.MaxOpenConns)
	}
}
