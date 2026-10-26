package marketplace

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/license"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	"github.com/plexusone/systemforge/identity/ent/seatassignment"
)

// EntLicenseService is an Ent-backed implementation of LicenseService.
type EntLicenseService struct {
	client    *ent.Client
	authzSync AuthzSyncer
}

// NewEntLicenseService creates a new Ent-backed license service.
func NewEntLicenseService(client *ent.Client, authzSync AuthzSyncer) *EntLicenseService {
	return &EntLicenseService{
		client:    client,
		authzSync: authzSync,
	}
}

// Grant creates a new license for an organization.
func (s *EntLicenseService) Grant(ctx context.Context, l *License) error {
	// Check if already licensed
	exists, err := s.client.License.Query().
		Where(
			license.ListingIDEQ(l.ListingID),
			license.OrganizationIDEQ(l.OrganizationID),
		).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("failed to check existing license: %w", err)
	}
	if exists {
		return ErrAlreadyLicensed
	}

	builder := s.client.License.Create().
		SetID(l.ID).
		SetListingID(l.ListingID).
		SetOrganizationID(l.OrganizationID).
		SetPurchasedBy(l.PurchasedBy).
		SetLicenseType(license.LicenseType(l.LicenseType)).
		SetValidFrom(l.ValidFrom)

	if l.Seats != nil {
		builder.SetSeats(*l.Seats)
	}
	if l.ValidUntil != nil {
		builder.SetValidUntil(*l.ValidUntil)
	}
	if l.StripeSubscriptionID != nil {
		builder.SetStripeSubscriptionID(*l.StripeSubscriptionID)
	}

	created, err := builder.Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to create license: %w", err)
	}

	// Update the input with generated values
	l.ID = created.ID
	l.CreatedAt = created.CreatedAt
	l.UpdatedAt = created.UpdatedAt

	// Sync to authorization system
	if s.authzSync != nil {
		if err := s.authzSync.SyncLicense(ctx, l); err != nil {
			return fmt.Errorf("failed to sync license to authz: %w", err)
		}
	}

	return nil
}

// Get retrieves a license by ID.
func (s *EntLicenseService) Get(ctx context.Context, id uuid.UUID) (*License, error) {
	entLicense, err := s.client.License.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrLicenseNotFound
		}
		return nil, fmt.Errorf("failed to get license: %w", err)
	}
	return entLicenseToLicense(entLicense), nil
}

// GetByListingAndOrg retrieves a license for a specific listing and organization.
func (s *EntLicenseService) GetByListingAndOrg(ctx context.Context, listingID, orgID uuid.UUID) (*License, error) {
	entLicense, err := s.client.License.Query().
		Where(
			license.ListingIDEQ(listingID),
			license.OrganizationIDEQ(orgID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrLicenseNotFound
		}
		return nil, fmt.Errorf("failed to get license: %w", err)
	}
	return entLicenseToLicense(entLicense), nil
}

// GetByStripeSubscriptionID retrieves the license a Stripe subscription
// pays for.
func (s *EntLicenseService) GetByStripeSubscriptionID(ctx context.Context, subscriptionID string) (*License, error) {
	entLicense, err := s.client.License.Query().
		Where(license.StripeSubscriptionIDEQ(subscriptionID)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrLicenseNotFound
		}
		return nil, fmt.Errorf("failed to get license by subscription: %w", err)
	}
	return entLicenseToLicense(entLicense), nil
}

// Update updates a license's details. UsedSeats is not written: it is
// maintained by AssignSeat and UnassignSeat, and writing a value read
// earlier would undo concurrent assignments.
func (s *EntLicenseService) Update(ctx context.Context, l *License) error {
	builder := s.client.License.UpdateOneID(l.ID).
		SetLicenseType(license.LicenseType(l.LicenseType)).
		SetValidFrom(l.ValidFrom)

	if l.Seats != nil {
		builder.SetSeats(*l.Seats)
	} else {
		builder.ClearSeats()
	}
	if l.ValidUntil != nil {
		builder.SetValidUntil(*l.ValidUntil)
	} else {
		builder.ClearValidUntil()
	}
	if l.StripeSubscriptionID != nil {
		builder.SetStripeSubscriptionID(*l.StripeSubscriptionID)
	}

	_, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrLicenseNotFound
		}
		return fmt.Errorf("failed to update license: %w", err)
	}
	return nil
}

// Revoke revokes a license, removing access.
func (s *EntLicenseService) Revoke(ctx context.Context, id uuid.UUID) error {
	// Get the license first
	l, err := s.Get(ctx, id)
	if err != nil {
		return err
	}

	// Delete all seat assignments
	_, err = s.client.SeatAssignment.Delete().
		Where(seatassignment.LicenseIDEQ(id)).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete seat assignments: %w", err)
	}

	// Delete the license
	err = s.client.License.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete license: %w", err)
	}

	// Sync revocation to authorization system
	if s.authzSync != nil {
		if err := s.authzSync.SyncLicenseRevocation(ctx, l); err != nil {
			return fmt.Errorf("failed to sync license revocation to authz: %w", err)
		}
	}

	return nil
}

// Check checks if an organization has a valid license for a listing.
func (s *EntLicenseService) Check(ctx context.Context, listingID, orgID uuid.UUID) (bool, error) {
	l, err := s.GetByListingAndOrg(ctx, listingID, orgID)
	if err != nil {
		if err == ErrLicenseNotFound {
			return false, nil
		}
		return false, err
	}
	return l.IsValid(), nil
}

// CheckPrincipal checks if a principal has access via license.
func (s *EntLicenseService) CheckPrincipal(ctx context.Context, listingID, principalID uuid.UUID) (bool, error) {
	// Find all licenses for this listing
	licenses, err := s.client.License.Query().
		Where(license.ListingIDEQ(listingID)).
		All(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to query licenses: %w", err)
	}

	now := time.Now()
	for _, l := range licenses {
		// Check if license is valid
		if now.Before(l.ValidFrom) {
			continue
		}
		if l.ValidUntil != nil && !now.Before(*l.ValidUntil) {
			continue
		}

		// For unlimited licenses, check if principal belongs to the org
		if l.LicenseType == license.LicenseTypeUnlimited {
			// TODO: Check org membership
			return true, nil
		}

		// For seat-based licenses, check seat assignment
		exists, err := s.client.SeatAssignment.Query().
			Where(
				seatassignment.LicenseIDEQ(l.ID),
				seatassignment.PrincipalIDEQ(principalID),
			).
			Exist(ctx)
		if err != nil {
			return false, fmt.Errorf("failed to check seat assignment: %w", err)
		}
		if exists {
			return true, nil
		}
	}

	return false, nil
}

// List retrieves licenses for an organization.
func (s *EntLicenseService) List(ctx context.Context, orgID uuid.UUID) ([]*License, error) {
	entLicenses, err := s.client.License.Query().
		Where(license.OrganizationIDEQ(orgID)).
		Order(ent.Desc(license.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list licenses: %w", err)
	}

	licenses := make([]*License, len(entLicenses))
	for i, el := range entLicenses {
		licenses[i] = entLicenseToLicense(el)
	}
	return licenses, nil
}

// ListByListing retrieves all licenses for a listing.
func (s *EntLicenseService) ListByListing(ctx context.Context, listingID uuid.UUID) ([]*License, error) {
	entLicenses, err := s.client.License.Query().
		Where(license.ListingIDEQ(listingID)).
		Order(ent.Desc(license.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list licenses: %w", err)
	}

	licenses := make([]*License, len(entLicenses))
	for i, el := range entLicenses {
		licenses[i] = entLicenseToLicense(el)
	}
	return licenses, nil
}

// AssignSeat assigns a user to a license seat.
//
// The seat is reserved by a conditional increment of used_seats in the same
// transaction as the assignment, so concurrent assignments cannot exceed
// the license's seats.
func (s *EntLicenseService) AssignSeat(ctx context.Context, assignment *SeatAssignment) error {
	var created *ent.SeatAssignment
	err := withTx(ctx, s.client, func(tx *ent.Tx) error {
		// Check if already assigned
		exists, err := tx.SeatAssignment.Query().
			Where(
				seatassignment.LicenseIDEQ(assignment.LicenseID),
				seatassignment.PrincipalIDEQ(assignment.PrincipalID),
			).
			Exist(ctx)
		if err != nil {
			return fmt.Errorf("failed to check existing assignment: %w", err)
		}
		if exists {
			return ErrSeatAlreadyAssigned
		}

		// Reserve a seat: increment used_seats only while one is free.
		n, err := tx.License.Update().
			Where(
				license.IDEQ(assignment.LicenseID),
				license.Or(
					license.SeatsIsNil(),
					predicate.License(sql.FieldsLT(license.FieldUsedSeats, license.FieldSeats)),
				),
			).
			AddUsedSeats(1).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to reserve seat: %w", err)
		}
		if n == 0 {
			found, err := tx.License.Query().Where(license.IDEQ(assignment.LicenseID)).Exist(ctx)
			if err != nil {
				return fmt.Errorf("failed to get license: %w", err)
			}
			if !found {
				return ErrLicenseNotFound
			}
			return ErrNoSeatsAvailable
		}

		created, err = tx.SeatAssignment.Create().
			SetID(assignment.ID).
			SetLicenseID(assignment.LicenseID).
			SetPrincipalID(assignment.PrincipalID).
			SetAssignedBy(assignment.AssignedBy).
			Save(ctx)
		if ent.IsConstraintError(err) {
			return ErrSeatAlreadyAssigned
		}
		if err != nil {
			return fmt.Errorf("failed to create seat assignment: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	assignment.ID = created.ID
	assignment.AssignedAt = created.AssignedAt

	// Sync to authorization system
	if s.authzSync != nil {
		if err := s.authzSync.SyncSeatAssignment(ctx, assignment); err != nil {
			return fmt.Errorf("failed to sync seat assignment to authz: %w", err)
		}
	}

	return nil
}

// UnassignSeat removes a user from a license seat.
func (s *EntLicenseService) UnassignSeat(ctx context.Context, licenseID, principalID uuid.UUID) error {
	err := withTx(ctx, s.client, func(tx *ent.Tx) error {
		found, err := tx.License.Query().Where(license.IDEQ(licenseID)).Exist(ctx)
		if err != nil {
			return fmt.Errorf("failed to get license: %w", err)
		}
		if !found {
			return ErrLicenseNotFound
		}

		// Delete the assignment
		affected, err := tx.SeatAssignment.Delete().
			Where(
				seatassignment.LicenseIDEQ(licenseID),
				seatassignment.PrincipalIDEQ(principalID),
			).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to delete seat assignment: %w", err)
		}
		if affected == 0 {
			return ErrSeatNotAssigned
		}

		// Release the seat with an atomic decrement.
		if _, err := tx.License.Update().
			Where(license.IDEQ(licenseID), license.UsedSeatsGT(0)).
			AddUsedSeats(-1).
			Save(ctx); err != nil {
			return fmt.Errorf("failed to update used seats: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Sync to authorization system
	if s.authzSync != nil {
		if err := s.authzSync.SyncSeatUnassignment(ctx, licenseID, principalID); err != nil {
			return fmt.Errorf("failed to sync seat unassignment to authz: %w", err)
		}
	}

	return nil
}

// withTx runs fn in a transaction, committing when fn returns nil and
// rolling back otherwise.
func withTx(ctx context.Context, client *ent.Client, fn func(tx *ent.Tx) error) error {
	tx, err := client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}
	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			return errors.Join(err, fmt.Errorf("rolling back: %w", rerr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// ListSeatAssignments retrieves all seat assignments for a license.
func (s *EntLicenseService) ListSeatAssignments(ctx context.Context, licenseID uuid.UUID) ([]*SeatAssignment, error) {
	entAssignments, err := s.client.SeatAssignment.Query().
		Where(seatassignment.LicenseIDEQ(licenseID)).
		Order(ent.Asc(seatassignment.FieldAssignedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list seat assignments: %w", err)
	}

	assignments := make([]*SeatAssignment, len(entAssignments))
	for i, ea := range entAssignments {
		assignments[i] = &SeatAssignment{
			ID:          ea.ID,
			LicenseID:   ea.LicenseID,
			PrincipalID: ea.PrincipalID,
			AssignedBy:  ea.AssignedBy,
			AssignedAt:  ea.AssignedAt,
		}
	}
	return assignments, nil
}

// entLicenseToLicense converts an Ent License to a marketplace.License.
func entLicenseToLicense(el *ent.License) *License {
	l := &License{
		ID:             el.ID,
		ListingID:      el.ListingID,
		OrganizationID: el.OrganizationID,
		LicenseType:    LicenseType(el.LicenseType),
		UsedSeats:      el.UsedSeats,
		ValidFrom:      el.ValidFrom,
		ValidUntil:     el.ValidUntil,
		PurchasedBy:    el.PurchasedBy,
		CreatedAt:      el.CreatedAt,
		UpdatedAt:      el.UpdatedAt,
	}

	if el.Seats != nil {
		l.Seats = el.Seats
	}
	if el.StripeSubscriptionID != nil {
		l.StripeSubscriptionID = el.StripeSubscriptionID
	}

	return l
}

// Ensure EntLicenseService implements LicenseService.
var _ LicenseService = (*EntLicenseService)(nil)
