package organization

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/license"
	"github.com/plexusone/systemforge/identity/ent/seatassignment"
)

// SeatSyncer removes a license seat from the authorization graph.
// marketplace.SpiceDBSyncer implements it.
type SeatSyncer interface {
	SyncSeatUnassignment(ctx context.Context, licenseID, principalID uuid.UUID) error
}

// WithSeatSyncer removes a removed member's license seats from the
// authorization graph. A deployment that writes seats to the graph must set
// it: without it the seats are released in the database only.
func WithSeatSyncer(syncer SeatSyncer) ServiceOption {
	return func(s *DefaultService) { s.seatSyncer = syncer }
}

// releaseSeats deletes the principal's seats on the organization's licenses,
// frees them, and returns the licenses they were on. Seats on other
// organizations' licenses are untouched.
func releaseSeats(ctx context.Context, client *ent.Client, principalID, organizationID uuid.UUID) ([]uuid.UUID, error) {
	seats, err := client.SeatAssignment.Query().
		Where(
			seatassignment.PrincipalIDEQ(principalID),
			seatassignment.HasLicenseWith(license.OrganizationID(organizationID)),
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read license seats: %w", err)
	}
	var released []uuid.UUID
	for _, seat := range seats {
		n, err := client.SeatAssignment.Delete().Where(seatassignment.ID(seat.ID)).Exec(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to release license seat: %w", err)
		}
		// Unassigned since it was read: its count is already freed.
		if n == 0 {
			continue
		}
		if _, err := client.License.Update().
			Where(license.ID(seat.LicenseID), license.UsedSeatsGT(0)).
			AddUsedSeats(-1).
			Save(ctx); err != nil {
			return nil, fmt.Errorf("failed to update used seats: %w", err)
		}
		released = append(released, seat.LicenseID)
	}
	return released, nil
}
