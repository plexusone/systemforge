package marketplace

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz/rebac/spicedb"
)

// SpiceDB resource types for marketplace entities.
const (
	ResourceTypeListing      = "listing"
	ResourceTypeLicense      = "license"
	ResourceTypeSubscription = "subscription"
	ResourceTypeOrganization = "organization"
	ResourceTypeCreatorOrg   = "creator_org"
	ResourceTypePrincipal    = "principal"
)

// SpiceDB relations for marketplace entities.
const (
	RelationCreatorOrg   = "creator_org"
	RelationOwner        = "owner"
	RelationLicensedOrg  = "licensed_org"
	RelationListing      = "listing"
	RelationOrganization = "organization"
	RelationPurchasedBy  = "purchased_by"
	RelationSeatHolder   = "seat_holder"
	RelationSubscriber   = "subscriber"
)

// SpiceDBSyncer implements AuthzSyncer using SpiceDB.
type SpiceDBSyncer struct {
	client *spicedb.Client
}

// NewSpiceDBSyncer creates a new SpiceDB syncer for marketplace entities.
func NewSpiceDBSyncer(client *spicedb.Client) *SpiceDBSyncer {
	return &SpiceDBSyncer{client: client}
}

// SyncListing syncs a listing to SpiceDB.
// Creates relationships:
//   - listing:id -> creator_org -> creator_org:creatorOrgId
//   - listing:id -> owner -> principal:ownerId
func (s *SpiceDBSyncer) SyncListing(ctx context.Context, listing *Listing) error {
	// Sync creator org relationship
	if err := s.client.WriteRelationship(ctx, &spicedb.Relationship{
		ResourceType: ResourceTypeListing,
		ResourceID:   listing.ID.String(),
		Relation:     RelationCreatorOrg,
		SubjectType:  ResourceTypeCreatorOrg,
		SubjectID:    listing.CreatorOrgID.String(),
	}); err != nil {
		return fmt.Errorf("syncing listing creator_org: %w", err)
	}

	// Sync owner relationship
	if err := s.client.WriteRelationship(ctx, &spicedb.Relationship{
		ResourceType: ResourceTypeListing,
		ResourceID:   listing.ID.String(),
		Relation:     RelationOwner,
		SubjectType:  ResourceTypePrincipal,
		SubjectID:    listing.OwnerID.String(),
	}); err != nil {
		return fmt.Errorf("syncing listing owner: %w", err)
	}

	return nil
}

// SyncLicense syncs a license grant to SpiceDB.
// Creates relationships:
//   - listing:listingId -> licensed_org -> organization:orgId
//   - license:id -> listing -> listing:listingId
//   - license:id -> organization -> organization:orgId
//   - license:id -> purchased_by -> principal:purchasedBy
func (s *SpiceDBSyncer) SyncLicense(ctx context.Context, license *License) error {
	// Grant licensed_org on the listing
	if err := s.client.WriteRelationship(ctx, &spicedb.Relationship{
		ResourceType: ResourceTypeListing,
		ResourceID:   license.ListingID.String(),
		Relation:     RelationLicensedOrg,
		SubjectType:  ResourceTypeOrganization,
		SubjectID:    license.OrganizationID.String(),
	}); err != nil {
		return fmt.Errorf("syncing license to listing: %w", err)
	}

	// License -> Listing
	if err := s.client.WriteRelationship(ctx, &spicedb.Relationship{
		ResourceType: ResourceTypeLicense,
		ResourceID:   license.ID.String(),
		Relation:     RelationListing,
		SubjectType:  ResourceTypeListing,
		SubjectID:    license.ListingID.String(),
	}); err != nil {
		return fmt.Errorf("syncing license listing relation: %w", err)
	}

	// License -> Organization
	if err := s.client.WriteRelationship(ctx, &spicedb.Relationship{
		ResourceType: ResourceTypeLicense,
		ResourceID:   license.ID.String(),
		Relation:     RelationOrganization,
		SubjectType:  ResourceTypeOrganization,
		SubjectID:    license.OrganizationID.String(),
	}); err != nil {
		return fmt.Errorf("syncing license organization relation: %w", err)
	}

	// License -> Purchased By
	if err := s.client.WriteRelationship(ctx, &spicedb.Relationship{
		ResourceType: ResourceTypeLicense,
		ResourceID:   license.ID.String(),
		Relation:     RelationPurchasedBy,
		SubjectType:  ResourceTypePrincipal,
		SubjectID:    license.PurchasedBy.String(),
	}); err != nil {
		return fmt.Errorf("syncing license purchaser: %w", err)
	}

	return nil
}

// SyncLicenseRevocation removes a license from SpiceDB.
// Removes relationships:
//   - listing:listingId -> licensed_org -> organization:orgId
func (s *SpiceDBSyncer) SyncLicenseRevocation(ctx context.Context, license *License) error {
	if err := s.client.DeleteRelationship(ctx, &spicedb.Relationship{
		ResourceType: ResourceTypeListing,
		ResourceID:   license.ListingID.String(),
		Relation:     RelationLicensedOrg,
		SubjectType:  ResourceTypeOrganization,
		SubjectID:    license.OrganizationID.String(),
	}); err != nil {
		return fmt.Errorf("removing license from listing: %w", err)
	}

	return nil
}

// SyncSeatAssignment syncs a seat assignment to SpiceDB.
// Creates relationship:
//   - license:licenseId -> seat_holder -> principal:principalId
func (s *SpiceDBSyncer) SyncSeatAssignment(ctx context.Context, assignment *SeatAssignment) error {
	if err := s.client.WriteRelationship(ctx, &spicedb.Relationship{
		ResourceType: ResourceTypeLicense,
		ResourceID:   assignment.LicenseID.String(),
		Relation:     RelationSeatHolder,
		SubjectType:  ResourceTypePrincipal,
		SubjectID:    assignment.PrincipalID.String(),
	}); err != nil {
		return fmt.Errorf("syncing seat assignment: %w", err)
	}

	return nil
}

// SyncSeatUnassignment removes a seat assignment from SpiceDB.
// Removes relationship:
//   - license:licenseId -> seat_holder -> principal:principalId
func (s *SpiceDBSyncer) SyncSeatUnassignment(ctx context.Context, licenseID, principalID uuid.UUID) error {
	if err := s.client.DeleteRelationship(ctx, &spicedb.Relationship{
		ResourceType: ResourceTypeLicense,
		ResourceID:   licenseID.String(),
		Relation:     RelationSeatHolder,
		SubjectType:  ResourceTypePrincipal,
		SubjectID:    principalID.String(),
	}); err != nil {
		return fmt.Errorf("removing seat assignment: %w", err)
	}

	return nil
}

// SyncSubscription syncs a subscription to SpiceDB.
// Creates relationships:
//   - subscription:id -> organization -> organization:orgId
func (s *SpiceDBSyncer) SyncSubscription(ctx context.Context, sub *Subscription) error {
	if err := s.client.WriteRelationship(ctx, &spicedb.Relationship{
		ResourceType: ResourceTypeSubscription,
		ResourceID:   sub.ID.String(),
		Relation:     RelationOrganization,
		SubjectType:  ResourceTypeOrganization,
		SubjectID:    sub.OrganizationID.String(),
	}); err != nil {
		return fmt.Errorf("syncing subscription organization: %w", err)
	}

	return nil
}

// Ensure SpiceDBSyncer implements AuthzSyncer.
var _ AuthzSyncer = (*SpiceDBSyncer)(nil)
