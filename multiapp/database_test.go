package multiapp

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/plexusone/systemforge/internal/pgtest"
)

func TestForSchemaRefusesUnsafeNames(t *testing.T) {
	db := &AppAwareDB{schemas: map[string]*SchemaDB{}}
	for _, name := range []string{"", "Mixed", "a-b", "a b", "app_x; DROP SCHEMA public CASCADE", "1abc", "x'y", `x"y`} {
		if _, err := db.ForSchema(name); err == nil {
			t.Errorf("ForSchema(%q) accepted", name)
		}
	}
	if sdb, err := db.ForSchema("app_one"); err != nil || sdb.Schema() != "app_one" {
		t.Errorf("ForSchema(app_one) = %v, %v", sdb, err)
	}
}

// A pool connected with one app's login serves that app's schema only.
func TestAppLoginServesOneSchema(t *testing.T) {
	db := &AppAwareDB{schemas: map[string]*SchemaDB{}}
	if _, err := db.ForSchema("app_one"); err != nil {
		t.Fatalf("first schema: %v", err)
	}
	if _, err := db.ForSchema("app_one"); err != nil {
		t.Fatalf("same schema again: %v", err)
	}
	if _, err := db.ForSchema("app_two"); !errors.Is(err, ErrSharedDatabaseLogin) {
		t.Errorf("second schema: %v, want ErrSharedDatabaseLogin", err)
	}
	ctx := WithAppContext(context.Background(), &AppContext{AppSlug: "two", DatabaseSchema: "app_two"})
	if err := NewEntConnHook(db).SetSchemaInTx(ctx, nil); !errors.Is(err, ErrSharedDatabaseLogin) {
		t.Errorf("hook with a second schema: %v, want ErrSharedDatabaseLogin", err)
	}
	if _, err := NewEntClientFactory(db).StdDBForSchema(ctx, "app_two"); !errors.Is(err, ErrSharedDatabaseLogin) {
		t.Errorf("factory with a second schema: %v, want ErrSharedDatabaseLogin", err)
	}
	if _, err := NewEntConnHook(nil).schemaFromContext(WithAppContext(context.Background(), &AppContext{DatabaseSchema: "app_one"})); err == nil {
		t.Error("hook without a database accepted a schema")
	}

	for _, opt := range []DBOption{AllowSharedLogin(), AsMigrationLogin()} {
		multi := &AppAwareDB{schemas: map[string]*SchemaDB{}}
		opt(&multi.opts)
		for _, s := range []string{"app_one", "app_two"} {
			if _, err := multi.ForSchema(s); err != nil {
				t.Errorf("multi-schema pool refused %s: %v", s, err)
			}
		}
	}
}

// TestSchemaDBIsolatesAppsOnAPooledConnection runs two applications over one
// small pool, so their calls share connections, and verifies each sees only
// its own schema and no connection leaves SchemaDB with a search_path set.
func TestSchemaDBIsolatesAppsOnAPooledConnection(t *testing.T) {
	ctx := context.Background()
	db, err := NewAppAwareDB(pgtest.DSN(t), AllowSharedLogin())
	if err != nil {
		t.Fatalf("NewAppAwareDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() }) //nolint:errcheck // test cleanup of a scratch database
	for _, s := range []string{"app_one", "app_two"} {
		if err := db.CreateSchema(ctx, s); err != nil {
			t.Fatalf("CreateSchema(%s): %v", s, err)
		}
	}
	one, err := db.ForSchema("app_one")
	if err != nil {
		t.Fatalf("ForSchema: %v", err)
	}
	two, err := db.ForSchema("app_two")
	if err != nil {
		t.Fatalf("ForSchema: %v", err)
	}

	for _, sdb := range []*SchemaDB{one, two} {
		if _, err := sdb.Exec(ctx, "CREATE TABLE notes (owner text)"); err != nil {
			t.Fatalf("%s: create table: %v", sdb.Schema(), err)
		}
		if _, err := sdb.Exec(ctx, "INSERT INTO notes (owner) VALUES ($1)", sdb.Schema()); err != nil {
			t.Fatalf("%s: insert: %v", sdb.Schema(), err)
		}
	}

	// Interleave the apps' calls: each sees its own table.
	for range 5 {
		for _, sdb := range []*SchemaDB{one, two, one, two} {
			var owner string
			if err := sdb.QueryRow(ctx, "SELECT owner FROM notes").Scan(&owner); err != nil || owner != sdb.Schema() {
				t.Fatalf("%s read %q, %v", sdb.Schema(), owner, err)
			}
		}
	}
	rows, err := one.Query(ctx, "SELECT owner FROM notes")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	n := 0
	for rows.Next() {
		n++
	}
	if rows.Err() != nil || n != 1 {
		t.Errorf("Query read %d rows, %v", n, rows.Err())
	}

	// A write through RETURNING is committed, not rolled back.
	var returned string
	if err := two.QueryRow(ctx, "INSERT INTO notes (owner) VALUES ('extra') RETURNING owner").Scan(&returned); err != nil || returned != "extra" {
		t.Fatalf("INSERT RETURNING = %q, %v", returned, err)
	}
	var count int
	if err := two.QueryRow(ctx, "SELECT count(*) FROM notes").Scan(&count); err != nil || count != 2 {
		t.Errorf("rows after INSERT RETURNING = %d, %v; want 2", count, err)
	}
	// A failing query ends its transaction instead of holding a connection.
	if err := one.QueryRow(ctx, "SELECT * FROM missing_table").Scan(&returned); err == nil {
		t.Error("a query on a missing table succeeded")
	}
	if _, err := one.Exec(ctx, "SELECT nope"); err == nil {
		t.Error("a bad statement succeeded")
	}

	// Transactions: committed work stays, rolled-back work goes.
	tx, err := one.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO notes (owner) VALUES ('rolled back')"); err != nil {
		t.Fatalf("tx insert: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	tx, err = one.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO notes (owner) VALUES ('kept')"); err != nil {
		t.Fatalf("tx insert: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := one.QueryRow(ctx, "SELECT count(*) FROM notes").Scan(&count); err != nil || count != 2 {
		t.Errorf("rows after rollback and commit = %d, %v; want 2", count, err)
	}

	// No connection goes back to the pool carrying a schema: ask every
	// connection the pool can hand out.
	pool := db.Pool()
	conns := make([]*pgxpool.Conn, 0, 4)
	for range 4 {
		c, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire: %v", err)
		}
		conns = append(conns, c)
		var sp string
		if err := c.QueryRow(ctx, "SHOW search_path").Scan(&sp); err != nil {
			t.Fatalf("SHOW search_path: %v", err)
		}
		if sp != `"$user", public` {
			t.Errorf("a pooled connection kept search_path %q", sp)
		}
	}
	for _, c := range conns {
		c.Release()
	}
}
