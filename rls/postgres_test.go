package rls_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/plexusone/systemforge/internal/pgtest"
	"github.com/plexusone/systemforge/rls"
)

// TestSetContextOnPostgres checks the session variables against a real
// server: set for the transaction, gone after it.
func TestSetContextOnPostgres(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("pgx", pgtest.DSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	db.SetMaxOpenConns(1) // the check after commit must use the same session
	cfg := rls.DefaultConfig()
	h := rls.NewHelper(cfg)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A value with a quote would break an interpolated statement.
	if err := h.SetContext(ctx, tx, "tenant-'1", "user-1"); err != nil {
		t.Fatalf("set context: %v", err)
	}
	var tenant, user string
	if err := tx.QueryRowContext(ctx, "SELECT current_setting($1, true), current_setting($2, true)",
		cfg.SessionVariable, cfg.UserSessionVariable).Scan(&tenant, &user); err != nil {
		t.Fatal(err)
	}
	if tenant != "tenant-'1" || user != "user-1" {
		t.Fatalf("in transaction: tenant %q, user %q", tenant, user)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var after sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT nullif(current_setting($1, true), '')", cfg.SessionVariable).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after.Valid {
		t.Fatalf("tenant outlived the transaction: %q", after.String)
	}
}
