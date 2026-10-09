package accesschange_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent/enttest"
)

func TestRecordSincePrune(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	p, org := uuid.New(), uuid.New()

	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: p, OrganizationID: &org, Reason: accesschange.MembershipRemoved})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	global, err := accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: p, Reason: accesschange.Deactivated})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if scoped.ChangedAt.IsZero() || time.Since(scoped.ChangedAt) > time.Minute {
		t.Errorf("ChangedAt = %v", scoped.ChangedAt)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// A rolled-back transaction leaves no record.
	tx, err = db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: p, Reason: accesschange.SessionsRevoked}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	got, err := accesschange.Since(ctx, db, time.Now().Add(-time.Hour), 0)
	if err != nil || len(got) != 2 {
		t.Fatalf("Since = %+v, %v; want the two committed changes", got, err)
	}
	if got[0].OrganizationID == nil || *got[0].OrganizationID != org || got[0].Reason != accesschange.MembershipRemoved || got[1].OrganizationID != nil {
		t.Errorf("changes = %+v", got)
	}
	if after, err := accesschange.Since(ctx, db, global.ChangedAt, 0); err != nil || len(after) != 0 {
		t.Errorf("Since the newest change = %+v, %v; want none", after, err)
	}

	// Invalid input is refused.
	tx, err = db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			t.Errorf("rollback: %v", err)
		}
	}()
	if _, err := accesschange.Record(ctx, tx, accesschange.Change{Reason: accesschange.Deactivated}); err == nil {
		t.Error("record without a principal was accepted")
	}
	if _, err := accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: p, Reason: "nonsense"}); err == nil {
		t.Error("record with an unknown reason was accepted")
	}

	// Prune keeps recent rows and drops old ones; PruneExpired keeps these.
	if n, err := accesschange.PruneExpired(ctx, db); err != nil || n != 0 {
		t.Errorf("PruneExpired = %d, %v; want 0", n, err)
	}
	if n, err := accesschange.Prune(ctx, db, time.Now().Add(time.Minute)); err != nil || n != 2 {
		t.Errorf("Prune = %d, %v; want 2", n, err)
	}
}

func TestPublish(t *testing.T) {
	var got []accesschange.Change
	sink := accesschange.SinkFunc(func(c accesschange.Change) { got = append(got, c) })
	accesschange.Publish(nil, accesschange.Change{}) // no sink: ignored
	accesschange.Publish(sink, accesschange.Change{Reason: accesschange.Deactivated}, accesschange.Change{Reason: accesschange.GrantReduced})
	if len(got) != 2 || got[1].Reason != accesschange.GrantReduced {
		t.Errorf("published = %+v", got)
	}
}

func TestSourceReadsChangesForRelyingParties(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	p, org := uuid.New(), uuid.New()
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: p, OrganizationID: &org, Reason: accesschange.AppRoleChanged})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: p, Reason: accesschange.Deactivated}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	src := accesschange.NewSource(db)
	got, err := src.AccessChangesSince(ctx, first.ChangedAt.Add(-time.Hour))
	if err != nil || len(got) != 2 {
		t.Fatalf("AccessChangesSince = %+v, %v", got, err)
	}
	if got[0].PrincipalID != p.String() || got[0].OrganizationID != org.String() || got[0].Reason != "app_role_changed" || got[1].OrganizationID != "" {
		t.Errorf("changes = %+v", got)
	}
	if listed, err := src.List(ctx, first.ChangedAt.Add(-time.Hour), 1); err != nil || len(listed) != 1 {
		t.Errorf("List with limit 1 = %+v, %v", listed, err)
	}
}
