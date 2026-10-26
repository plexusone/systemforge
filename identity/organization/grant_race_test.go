package organization_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/graphlock"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/internal/pgtest"
	"github.com/plexusone/systemforge/internal/syncrec"
)

func newPostgres(t *testing.T) *ent.Client {
	t.Helper()
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, pgtest.Open(t))))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// A membership added while a revocation of the principal's access is in
// progress, and removed by that revocation after the addition committed,
// is not written to the graph: the post-commit write waits for the
// revocation's graph lock and reads the membership again.
func TestGrantDoesNotUndoARevocationPostgres(t *testing.T) {
	ctx := context.Background()
	db := newPostgres(t)
	rec := syncrec.New()
	svc := organization.NewService(db, organization.WithAuthzSyncer(rec))
	owner := newHuman(t, db, "owner-"+uuid.NewString()+"@example.com")
	org, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme-" + uuid.NewString()[:8], OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatal(err)
	}
	p := newHuman(t, db, "member-"+uuid.NewString()+"@example.com")

	revocation, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := graphlock.Lock(ctx, revocation, graphlock.Principal(p)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: p, Role: organization.RoleMember})
		done <- err
	}()
	member := principalmembership.And(principalmembership.OrganizationID(org.ID), principalmembership.PrincipalID(p))
	waitFor(t, func() bool {
		ok, err := db.PrincipalMembership.Query().Where(member).Exist(ctx)
		return err == nil && ok
	})
	if _, err := revocation.PrincipalMembership.Delete().Where(member).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := revocation.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if calls := rec.Calls(); slices.Contains(calls, fmt.Sprintf("AddOrgMembership:%s:%s:member", p, org.ID)) {
		t.Errorf("the graph got a membership the revocation had removed; calls %v", calls)
	}

	// Without a revocation the same grant is written.
	rec.Reset()
	q := newHuman(t, db, "member-"+uuid.NewString()+"@example.com")
	if _, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: q, Role: organization.RoleMember}); err != nil {
		t.Fatal(err)
	}
	if calls := rec.Calls(); !slices.Contains(calls, fmt.Sprintf("AddOrgMembership:%s:%s:member", q, org.ID)) {
		t.Errorf("membership not written; calls %v", calls)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met within 10s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
