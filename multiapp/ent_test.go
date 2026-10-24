package multiapp

import (
	"context"
	"database/sql"
	"testing"

	"github.com/plexusone/systemforge/internal/pgtest"
)

var unsafeSchemaNames = []string{"Mixed", "a-b", "app_x; DROP SCHEMA public CASCADE", "x'y", `x"y`, "app_x, public"}

// Every path that puts a schema name into SQL or a connection parameter
// refuses one that is not a plain identifier, before touching the database.
func TestSchemaPathsRefuseUnsafeNames(t *testing.T) {
	ctx := context.Background()
	f := NewEntClientFactory(nil)
	h := NewEntConnHook(nil)
	for _, name := range unsafeSchemaNames {
		if _, err := f.StdDBForSchema(ctx, name); err == nil {
			t.Errorf("StdDBForSchema(%q) accepted", name)
		}
		if _, err := f.PgxConnWithSchema(ctx, name); err == nil {
			t.Errorf("PgxConnWithSchema(%q) accepted", name)
		}
		actx := WithAppContext(ctx, &AppContext{AppSlug: "x", DatabaseSchema: name})
		if err := h.SetSchemaInTx(actx, nil); err == nil {
			t.Errorf("SetSchemaInTx(%q) accepted", name)
		}
		if err := h.SetSchemaFromContext(actx, nil); err == nil { //nolint:staticcheck // the deprecated hook must validate too
			t.Errorf("SetSchemaFromContext(%q) accepted", name)
		}
	}
	if err := h.SetSchemaInTx(ctx, nil); err != ErrNoAppContext {
		t.Errorf("SetSchemaInTx without an app context: %v", err)
	}
}

// SetSchemaInTx scopes the schema to the transaction: a pooled connection
// returns to the pool with its default search_path.
func TestSetSchemaInTxEndsWithTheTransaction(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("pgx", pgtest.DSN(t))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA app_one"); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	h := NewEntConnHook(nil)
	actx := WithAppContext(ctx, &AppContext{AppSlug: "one", DatabaseSchema: "app_one"})
	tx, err := db.BeginTx(actx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := h.SetSchemaInTx(actx, tx); err != nil {
		t.Fatalf("SetSchemaInTx: %v", err)
	}
	var inTx string
	if err := tx.QueryRowContext(actx, "SHOW search_path").Scan(&inTx); err != nil {
		t.Fatalf("SHOW in tx: %v", err)
	}
	if inTx != "app_one, public" {
		t.Errorf("search_path in the transaction = %q", inTx)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	var after string
	if err := db.QueryRowContext(ctx, "SHOW search_path").Scan(&after); err != nil {
		t.Fatalf("SHOW after: %v", err)
	}
	if after != `"$user", public` {
		t.Errorf("the pooled connection kept search_path %q", after)
	}
}
