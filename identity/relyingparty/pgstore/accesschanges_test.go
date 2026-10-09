package pgstore

import (
	"context"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/internal/pgtest"
)

// TestReplicaPollsAccessChangesFromTheSharedDatabase runs two "instances"
// over one PostgreSQL database: a change SystemAuth records on one is seen
// by the other's cache through the poller, which is how replicas of a
// monolith share access changes (ADR-010 decision 4).
func TestReplicaPollsAccessChangesFromTheSharedDatabase(t *testing.T) {
	ctx := context.Background()
	sqlDB := pgtest.Open(t)
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sqlDB)))
	if err := db.Schema.Create(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}

	// Instance A runs SystemAuth; instance B only polls.
	orgs := organization.NewService(db)
	person := func(email string) uuid.UUID {
		p, err := db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier(email).SetDisplayName(email).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	owner, kim := person("owner@example.com"), person("kim@example.com")
	org, err := orgs.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orgs.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: kim, Role: organization.RoleMember}); err != nil {
		t.Fatal(err)
	}

	cacheB := relyingparty.NewRevocationCache(relyingparty.WithSuspectStart())
	poller := relyingparty.NewAccessChangePoller(NewAccessChangeSource(sqlDB), cacheB)
	issued := time.Now()
	if err := poller.Poll(ctx); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if cacheB.Suspect() {
		t.Error("the first poll left the replica suspect")
	}
	if cacheB.ChangedAt(kim.String(), org.ID.String()).After(issued) {
		t.Fatal("a change was seen before it happened")
	}

	if err := orgs.RemoveMember(ctx, org.ID, kim); err != nil {
		t.Fatal(err)
	}
	if err := poller.Poll(ctx); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if cacheB.Accept(kim.String(), org.ID.String(), issued) {
		t.Error("replica B still accepts a token issued before the removal")
	}
	if !cacheB.Accept(owner.String(), org.ID.String(), issued) {
		t.Error("replica B refused an unaffected principal")
	}
}

// TestAccessChangeSourcePages verifies that the source returns every row
// across page boundaries, in order, and none at or before since.
func TestAccessChangeSourcePages(t *testing.T) {
	ctx := context.Background()
	sqlDB := pgtest.Open(t)
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sqlDB)))
	if err := db.Schema.Create(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	const n = 2*accessChangesPageSize + 37
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	creates := make([]*ent.AccessChangeCreate, n)
	for i := range creates {
		// Several rows share a timestamp, so the keyset must use the id.
		creates[i] = db.AccessChange.Create().SetPrincipalID(uuid.New()).
			SetReason("deactivated").SetChangedAt(base.Add(time.Duration(i/3) * time.Millisecond))
	}
	if _, err := db.AccessChange.CreateBulk(creates...).Save(ctx); err != nil {
		t.Fatal(err)
	}

	src := NewAccessChangeSource(sqlDB)
	got, err := src.AccessChangesSince(ctx, base.Add(-time.Second))
	if err != nil || len(got) != n {
		t.Fatalf("got %d changes, %v; want %d", len(got), err, n)
	}
	for i := 1; i < len(got); i++ {
		if got[i].ChangedAt.Before(got[i-1].ChangedAt) {
			t.Fatalf("out of order at %d", i)
		}
	}
	seen := map[string]bool{}
	for _, c := range got {
		seen[c.PrincipalID] = true
	}
	if len(seen) != n {
		t.Errorf("%d distinct principals, want %d (a page boundary lost or repeated rows)", len(seen), n)
	}
	last := got[len(got)-1].ChangedAt
	if after, err := src.AccessChangesSince(ctx, last); err != nil || len(after) != 0 {
		t.Errorf("since the newest = %d, %v; want none", len(after), err)
	}
}
