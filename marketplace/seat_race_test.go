package marketplace

import (
	"context"
	"errors"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/seatassignment"
	"github.com/plexusone/systemforge/identity/graphlock"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/internal/pgtest"
)

// blockedFor is how long a call waiting on the principal's lock must stay
// unfinished before the test releases it.
const blockedFor = 500 * time.Millisecond

func newPostgresFixture(t *testing.T, ctx context.Context) removalFixture {
	t.Helper()
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, pgtest.Open(t))))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return newRemovalFixtureOn(t, ctx, db)
}

// lockPrincipal opens a transaction holding the principal's lock.
func lockPrincipal(t *testing.T, ctx context.Context, db *ent.Client, principalID uuid.UUID) *ent.Tx {
	t.Helper()
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := graphlock.Lock(ctx, tx, graphlock.Principal(principalID)); err != nil {
		t.Fatal(err)
	}
	return tx
}

// commitWhileBlocked runs call, requires it to wait for tx, commits tx and
// returns the call's error.
func commitWhileBlocked(t *testing.T, tx *ent.Tx, call func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- call() }()
	select {
	case err := <-done:
		t.Errorf("the call did not wait for the principal's lock; it returned %v", err)
		if cerr := tx.Commit(); cerr != nil {
			t.Fatal(cerr)
		}
		return err
	case <-time.After(blockedFor):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the call did not finish within 10s")
		return nil
	}
}

// An assignment that starts while a removal is in progress waits for it, and
// then finds the principal gone.
func TestAssignSeatDuringRemovalPostgres(t *testing.T) {
	ctx := context.Background()
	f := newPostgresFixture(t, ctx)
	if err := f.licenses.UnassignSeat(ctx, f.licenseID, f.leaving); err != nil {
		t.Fatal(err)
	}
	removal := lockPrincipal(t, ctx, f.client, f.leaving)
	if _, err := removal.PrincipalMembership.Delete().Where(
		principalmembership.PrincipalID(f.leaving),
		principalmembership.OrganizationID(f.orgID),
	).Exec(ctx); err != nil {
		t.Fatal(err)
	}

	err := commitWhileBlocked(t, removal, func() error {
		return f.licenses.AssignSeat(ctx, &SeatAssignment{
			ID: uuid.New(), LicenseID: f.licenseID, PrincipalID: f.leaving, AssignedBy: f.staying,
		})
	})
	if !errors.Is(err, ErrNotOrganizationMember) {
		t.Errorf("AssignSeat() error = %v, want %v", err, ErrNotOrganizationMember)
	}
	if used, holders := f.seatsOn(t, ctx, f.licenseID); used != 1 || holders[f.leaving] {
		t.Errorf("license: used = %d, holders = %v; want no seat for the removed member", used, holders)
	}
}

// A removal that starts while an assignment is in progress waits for it, and
// then releases the new seat too.
func TestRemoveMemberDuringAssignmentPostgres(t *testing.T) {
	ctx := context.Background()
	f := newPostgresFixture(t, ctx)
	if err := f.licenses.UnassignSeat(ctx, f.licenseID, f.leaving); err != nil {
		t.Fatal(err)
	}
	assignment := lockPrincipal(t, ctx, f.client, f.leaving)
	if _, err := assignment.SeatAssignment.Create().
		SetLicenseID(f.licenseID).
		SetPrincipalID(f.leaving).
		SetAssignedBy(f.staying).
		Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := assignment.License.UpdateOneID(f.licenseID).AddUsedSeats(1).Save(ctx); err != nil {
		t.Fatal(err)
	}

	err := commitWhileBlocked(t, assignment, func() error {
		return organization.NewService(f.client).RemoveMember(ctx, f.orgID, f.leaving)
	})
	if err != nil {
		t.Fatalf("RemoveMember() error = %v", err)
	}
	held, err := f.client.SeatAssignment.Query().Where(
		seatassignment.LicenseID(f.licenseID),
		seatassignment.PrincipalID(f.leaving),
	).Exist(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if used, _ := f.seatsOn(t, ctx, f.licenseID); held || used != 1 {
		t.Errorf("seat held = %v, used = %d; want the seat released", held, used)
	}
}

// An unassignment waits for whoever holds the principal's lock, such as a graph
// write of the same seat, so the write cannot land after the removal.
func TestUnassignSeatWaitsForPrincipalLockPostgres(t *testing.T) {
	ctx := context.Background()
	f := newPostgresFixture(t, ctx)
	holder := lockPrincipal(t, ctx, f.client, f.leaving)

	err := commitWhileBlocked(t, holder, func() error {
		return f.licenses.UnassignSeat(ctx, f.licenseID, f.leaving)
	})
	if err != nil {
		t.Fatalf("UnassignSeat() error = %v", err)
	}
}
