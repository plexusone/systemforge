package graphlock_test

import (
	"context"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/graphlock"
	"github.com/plexusone/systemforge/internal/pgtest"

	_ "github.com/mattn/go-sqlite3"
)

func TestKeysSortOrganizationsFirst(t *testing.T) {
	id := uuid.New()
	if graphlock.Organization(id) >= graphlock.Principal(id) {
		t.Errorf("organization key %q does not sort before principal key %q", graphlock.Organization(id), graphlock.Principal(id))
	}
}

// On SQLite, which has no advisory locks, Lock succeeds and leaves the
// transaction usable.
func TestLockIsANoOpOnSQLite(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := graphlock.Lock(ctx, tx, graphlock.Principal(uuid.New())); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := tx.Organization.Query().Count(ctx); err != nil {
		t.Fatalf("query after Lock: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// On PostgreSQL a second transaction locking the same key waits until the
// first ends; a different key does not wait.
func TestLockSerializesOnPostgres(t *testing.T) {
	ctx := context.Background()
	sqlDB := pgtest.Open(t)
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sqlDB)))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	key := graphlock.Principal(uuid.New())

	first, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := graphlock.Lock(ctx, first, key); err != nil {
		t.Fatalf("first Lock: %v", err)
	}

	other, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := graphlock.Lock(ctx, other, graphlock.Principal(uuid.New())); err != nil {
		t.Fatalf("Lock of another key: %v", err)
	}
	if err := other.Commit(); err != nil {
		t.Fatal(err)
	}

	acquired := make(chan error, 1)
	go func() {
		second, err := db.Tx(ctx)
		if err != nil {
			acquired <- err
			return
		}
		if err := graphlock.Lock(ctx, second, key); err != nil {
			acquired <- err
			return
		}
		acquired <- second.Commit()
	}()
	select {
	case err := <-acquired:
		t.Fatalf("second Lock returned while the first transaction held the key: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := first.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-acquired:
		if err != nil {
			t.Fatalf("second Lock: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("second Lock still waiting after the first transaction committed")
	}
}
