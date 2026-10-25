package approle_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	entapprole "github.com/plexusone/systemforge/identity/ent/approle"
	"github.com/plexusone/systemforge/identity/graphlock"
	"github.com/plexusone/systemforge/internal/pgtest"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// A role assigned while a revocation of the principal's access is in
// progress, and removed by it after the assignment committed, is not
// written to the graph.
func TestAssignDoesNotUndoARevocationPostgres(t *testing.T) {
	ctx := context.Background()
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, pgtest.Open(t))))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	f := newFixtureOn(t, db)
	rec := syncrec.New()
	svc := approle.NewService(db, f.reg, approle.EntitleAll(f.reg), approle.WithAuthzSyncer(rec, authz.SyncModeStrict))

	revocation, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := graphlock.Lock(ctx, revocation, graphlock.Principal(f.member)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := svc.Assign(ctx, f.in(f.member, "alpha", "viewer"))
		done <- err
	}()
	held := entapprole.And(entapprole.PrincipalID(f.member), entapprole.Application("alpha"))
	deadline := time.Now().Add(10 * time.Second)
	for {
		ok, err := db.AppRole.Query().Where(held).Exist(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("role not assigned within 10s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := revocation.AppRole.Delete().Where(held).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := revocation.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if calls := rec.Calls(); slices.Contains(calls, fmt.Sprintf("AddAppRole:%s:%s:alpha:viewer", f.member, f.org.ID)) {
		t.Errorf("the graph got a role the revocation had removed; calls %v", calls)
	}

	// Without a revocation the same assignment is written.
	if _, err := svc.Assign(ctx, f.in(f.admin, "alpha", "viewer")); err != nil {
		t.Fatal(err)
	}
	if calls := rec.Calls(); !slices.Contains(calls, fmt.Sprintf("AddAppRole:%s:%s:alpha:viewer", f.admin, f.org.ID)) {
		t.Errorf("role not written; calls %v", calls)
	}
}
