package marketplace

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/seatassignment"
)

// An assignment that runs while another is between its capacity check and
// its write must not exceed the license's seats, and used_seats must match
// the assignments. A hook runs the second assignment just before the
// first one's seat assignment is inserted.
func TestAssignSeatInterleavedNeverExceedsSeats(t *testing.T) {
	ctx := context.Background()
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	listingSvc := NewEntListingService(client, nil)
	svc := NewEntLicenseService(client, nil)
	orgID, buyer, listingID := createTestLicenseFixtures(t, ctx, client, listingSvc)

	const seats = 1
	n := seats
	lic := &License{ID: uuid.New(), ListingID: listingID, OrganizationID: orgID,
		LicenseType: LicenseSeatBased, Seats: &n, ValidFrom: time.Now(), PurchasedBy: buyer}
	if err := svc.Grant(ctx, lic); err != nil {
		t.Fatal(err)
	}
	other, err := client.Principal.Create().SetType("human").
		SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("Other").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var (
		interleaved bool
		otherErr    error
	)
	client.SeatAssignment.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if !interleaved && m.Op().Is(ent.OpCreate) {
				interleaved = true
				otherErr = svc.AssignSeat(ctx, &SeatAssignment{ID: uuid.New(), LicenseID: lic.ID, PrincipalID: other.ID, AssignedBy: buyer})
			}
			return next.Mutate(ctx, m)
		})
	})

	firstErr := svc.AssignSeat(ctx, &SeatAssignment{ID: uuid.New(), LicenseID: lic.ID, PrincipalID: buyer, AssignedBy: buyer})
	t.Logf("first assignment: %v, interleaved assignment: %v", firstErr, otherErr)

	assigned, err := client.SeatAssignment.Query().Where(seatassignment.LicenseIDEQ(lic.ID)).Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.License.Get(ctx, lic.ID)
	if err != nil {
		t.Fatal(err)
	}
	if assigned > seats {
		t.Errorf("%d seat assignments exist, want at most %d", assigned, seats)
	}
	if got.UsedSeats != assigned {
		t.Errorf("used_seats = %d, want %d (the assignments)", got.UsedSeats, assigned)
	}
	if firstErr == nil && otherErr == nil {
		t.Error("both assignments succeeded on a one-seat license")
	}
	if firstErr != nil && !errors.Is(firstErr, ErrNoSeatsAvailable) && otherErr != nil {
		t.Errorf("no assignment succeeded: %v / %v", firstErr, otherErr)
	}
}

// Update must not overwrite used_seats with a stale value.
func TestUpdateKeepsUsedSeats(t *testing.T) {
	ctx := context.Background()
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	listingSvc := NewEntListingService(client, nil)
	svc := NewEntLicenseService(client, nil)
	orgID, buyer, listingID := createTestLicenseFixtures(t, ctx, client, listingSvc)

	n := 3
	lic := &License{ID: uuid.New(), ListingID: listingID, OrganizationID: orgID,
		LicenseType: LicenseSeatBased, Seats: &n, ValidFrom: time.Now(), PurchasedBy: buyer}
	if err := svc.Grant(ctx, lic); err != nil {
		t.Fatal(err)
	}
	stale, err := svc.Get(ctx, lic.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.AssignSeat(ctx, &SeatAssignment{ID: uuid.New(), LicenseID: lic.ID, PrincipalID: buyer, AssignedBy: buyer}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Update(ctx, stale); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Get(ctx, lic.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.UsedSeats != 1 {
		t.Fatalf("used_seats = %d after Update with a stale license, want 1", got.UsedSeats)
	}
}
