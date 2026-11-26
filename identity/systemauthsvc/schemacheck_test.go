package systemauthsvc_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
	"github.com/plexusone/systemforge/internal/pgtest"
)

// checkSchemaScenarios runs the schema check against a database of the given
// configuration: empty, migrated, and migrated then missing one column.
func checkSchemaScenarios(t *testing.T, db *systemauth.DatabaseConfig) {
	t.Helper()
	ctx := t.Context()
	key := testKey(t)
	cfg := &systemauthsvc.Config{Issuer: "https://auth.example.com", Database: db}
	start := func(opts systemauthsvc.Options) (*systemauthsvc.Service, error) {
		opts.SigningKey, opts.Logger, opts.Dev = key, discardLogger(), true
		return systemauthsvc.New(ctx, cfg, opts)
	}

	// A database nobody migrated: the check says so, and New refuses to start.
	err := systemauthsvc.CheckMigrations(ctx, cfg)
	if !errors.Is(err, systemauthsvc.ErrSchemaBehind) {
		t.Fatalf("CheckMigrations on an empty database = %v, want ErrSchemaBehind", err)
	}
	// With every table missing, the list is cut rather than printing them all.
	for _, want := range []string{"missing tables: sf_", " and ", " more)", "systemauth migrate"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if len(err.Error()) > 600 {
		t.Errorf("the error is %d characters: a long list was not cut", len(err.Error()))
	}
	if s, err := start(systemauthsvc.Options{}); !errors.Is(err, systemauthsvc.ErrSchemaBehind) {
		if s != nil {
			closeService(t, s)
		}
		t.Fatalf("New without migrations on an empty database = %v, want ErrSchemaBehind", err)
	}

	// Migrated: the check passes, New starts with or without running it, and
	// running the migration again changes nothing.
	if err := systemauthsvc.Migrate(ctx, cfg); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := systemauthsvc.CheckMigrations(ctx, cfg); err != nil {
		t.Fatalf("CheckMigrations after Migrate: %v", err)
	}
	s, err := start(systemauthsvc.Options{})
	if err != nil {
		t.Fatalf("New on a migrated database: %v", err)
	}
	closeService(t, s)

	// A database one release behind: one column missing, named exactly.
	d, err := systemauthsvc.OpenDatabase(db)
	if err != nil {
		t.Fatalf("OpenDatabase: %v", err)
	}
	if _, err := d.DB.ExecContext(ctx, `ALTER TABLE sf_verification_tokens DROP COLUMN attempts`); err != nil {
		t.Fatalf("dropping a column: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}
	err = systemauthsvc.CheckMigrations(ctx, cfg)
	if !errors.Is(err, systemauthsvc.ErrSchemaBehind) || !strings.Contains(err.Error(), "missing columns: sf_verification_tokens.attempts") ||
		strings.Contains(err.Error(), "missing tables") {
		t.Fatalf("CheckMigrations with one column missing = %v, want exactly that column", err)
	}
	if s, err := start(systemauthsvc.Options{}); !errors.Is(err, systemauthsvc.ErrSchemaBehind) {
		if s != nil {
			closeService(t, s)
		}
		t.Fatalf("New with a column missing = %v, want ErrSchemaBehind", err)
	}

	// The opt-out starts anyway, for a host that manages its schema otherwise.
	s, err = start(systemauthsvc.Options{SkipSchemaCheck: true})
	if err != nil {
		t.Fatalf("New with SkipSchemaCheck: %v", err)
	}
	closeService(t, s)

	// Running the migration at startup repairs it, and the check then passes.
	s, err = start(systemauthsvc.Options{Migrate: true})
	if err != nil {
		t.Fatalf("New with Migrate: %v", err)
	}
	closeService(t, s)
	if err := systemauthsvc.CheckMigrations(ctx, cfg); err != nil {
		t.Fatalf("CheckMigrations after Migrate repaired the column: %v", err)
	}
}

func TestSchemaCheckSQLite(t *testing.T) {
	checkSchemaScenarios(t, &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)})
}

func TestSchemaCheckPostgres(t *testing.T) {
	checkSchemaScenarios(t, &systemauth.DatabaseConfig{Driver: "postgres", DSN: pgtest.DSN(t)})
}

func TestCheckMigrationsNeedsADatabase(t *testing.T) {
	if err := systemauthsvc.CheckMigrations(t.Context(), &systemauthsvc.Config{}); err == nil {
		t.Fatal("CheckMigrations without a database succeeded")
	}
}
