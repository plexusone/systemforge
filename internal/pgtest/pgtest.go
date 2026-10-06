// Package pgtest provides throwaway PostgreSQL databases for integration
// tests. Tests are skipped unless SF_TEST_PG_DSN points at a server where
// the user may create databases, for example:
//
//	SF_TEST_PG_DSN='postgres://user@127.0.0.1:5432/postgres?sslmode=disable'
package pgtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	// pgx registers the "pgx" database/sql driver.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// EnvDSN names the environment variable holding the admin DSN.
const EnvDSN = "SF_TEST_PG_DSN"

// DSN returns a DSN for a fresh scratch database that is dropped when the
// test ends. It skips the test when EnvDSN is unset.
func DSN(t testing.TB) string {
	t.Helper()
	admin := os.Getenv(EnvDSN)
	if admin == "" {
		t.Skipf("%s not set; skipping PostgreSQL integration test", EnvDSN)
	}
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parsing %s: %v", EnvDSN, err)
	}

	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random name: %v", err)
	}
	name := "sf_test_" + hex.EncodeToString(b)

	adminDB, err := sql.Open("pgx", admin)
	if err != nil {
		t.Fatalf("opening admin database: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// name is generated from hex digits only, so it is safe to inline.
	if _, err := adminDB.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		closeDB(t, adminDB)
		t.Fatalf("creating scratch database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := adminDB.ExecContext(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("dropping scratch database %s: %v", name, err)
		}
		closeDB(t, adminDB)
	})

	u.Path = "/" + name
	return u.String()
}

// Open returns a *sql.DB for a fresh scratch database, closed and dropped
// when the test ends. It skips the test when EnvDSN is unset.
func Open(t testing.TB) *sql.DB {
	t.Helper()
	dsn := DSN(t)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("opening scratch database: %v", err)
	}
	// Registered after DSN's cleanup, so it runs first (LIFO).
	t.Cleanup(func() { closeDB(t, db) })
	return db
}

func closeDB(t testing.TB, db *sql.DB) {
	t.Helper()
	if err := db.Close(); err != nil {
		t.Errorf("closing database: %v", err)
	}
}
