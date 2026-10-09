package approle_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/internal/pgtest"
)

// TestSeatLimitConcurrentPostgres starts many assignments at once against
// a seat limit and requires exactly the limit to succeed. Each caller
// uses its own Service, as separate server processes would, so only the
// database lock can serialize them.
func TestSeatLimitConcurrentPostgres(t *testing.T) {
	ctx := context.Background()
	sqlDB := pgtest.Open(t)
	sqlDB.SetMaxOpenConns(30)
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sqlDB)))
	if err := db.Schema.Create(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	const limit, callers = 3, 20
	seats := limit
	grants := approle.WithEntitlementGrants(func(context.Context, uuid.UUID) (map[string]approle.Grant, error) {
		return map[string]approle.Grant{"alpha": {SeatLimit: &seats}}, nil
	})
	f := newFixtureOn(t, db, grants)
	members := make([]uuid.UUID, callers)
	for i := range members {
		members[i] = f.human(fmt.Sprintf("member%d@example.com", i))
		f.addMember(members[i], organization.RoleMember)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, callers)
	for i := range members {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc := approle.NewService(db, f.reg, grants)
			<-start
			_, errs[i] = svc.Assign(ctx, f.in(members[i], "alpha", "viewer"))
		}()
	}
	close(start)
	wg.Wait()

	ok := 0
	for i, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, approle.ErrNoSeats):
			t.Errorf("caller %d: %v", i, err)
		}
	}
	if ok != limit {
		t.Errorf("%d assignments succeeded, want %d", ok, limit)
	}
	held, err := f.svc.ListForOrganization(ctx, f.org.ID, "alpha")
	if err != nil || len(held) != limit {
		t.Errorf("stored roles = %d, %v; want %d", len(held), err, limit)
	}
}
