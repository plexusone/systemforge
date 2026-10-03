package marketplace

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/listing"
)

// EntListingService is an Ent-backed implementation of ListingService.
type EntListingService struct {
	client    *ent.Client
	authzSync AuthzSyncer
}

// NewEntListingService creates a new Ent-backed listing service.
func NewEntListingService(client *ent.Client, authzSync AuthzSyncer) *EntListingService {
	return &EntListingService{
		client:    client,
		authzSync: authzSync,
	}
}

// Create creates a new listing in draft status.
func (s *EntListingService) Create(ctx context.Context, l *Listing) error {
	builder := s.client.Listing.Create().
		SetID(l.ID).
		SetCreatorOrgID(l.CreatorOrgID).
		SetOwnerID(l.OwnerID).
		SetProductType(l.ProductType).
		SetTitle(l.Title).
		SetPricingModel(listing.PricingModel(l.PricingModel)).
		SetPriceCents(l.PriceCents).
		SetCurrency(l.Currency).
		SetStatus(listing.StatusDraft)

	if l.ProductID != uuid.Nil {
		builder.SetProductID(l.ProductID)
	}
	if l.Description != "" {
		builder.SetDescription(l.Description)
	}
	if l.Metadata != nil {
		builder.SetMetadata(l.Metadata)
	}

	created, err := builder.Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to create listing: %w", err)
	}

	// Update the input with generated values
	l.ID = created.ID
	l.Status = ListingStatusDraft
	l.CreatedAt = created.CreatedAt
	l.UpdatedAt = created.UpdatedAt

	return nil
}

// Get retrieves a listing by ID.
func (s *EntListingService) Get(ctx context.Context, id uuid.UUID) (*Listing, error) {
	entListing, err := s.client.Listing.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrListingNotFound
		}
		return nil, fmt.Errorf("failed to get listing: %w", err)
	}
	return entListingToListing(entListing), nil
}

// GetByProduct retrieves a listing by product type and ID.
func (s *EntListingService) GetByProduct(ctx context.Context, productType string, productID uuid.UUID) (*Listing, error) {
	entListing, err := s.client.Listing.Query().
		Where(
			listing.ProductTypeEQ(productType),
			listing.ProductIDEQ(productID),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrListingNotFound
		}
		return nil, fmt.Errorf("failed to get listing by product: %w", err)
	}
	return entListingToListing(entListing), nil
}

// Update updates a listing's details.
func (s *EntListingService) Update(ctx context.Context, l *Listing) error {
	builder := s.client.Listing.UpdateOneID(l.ID).
		SetTitle(l.Title).
		SetPricingModel(listing.PricingModel(l.PricingModel)).
		SetPriceCents(l.PriceCents).
		SetCurrency(l.Currency)

	if l.ProductID != uuid.Nil {
		builder.SetProductID(l.ProductID)
	}
	if l.Description != "" {
		builder.SetDescription(l.Description)
	} else {
		builder.ClearDescription()
	}
	if l.Metadata != nil {
		builder.SetMetadata(l.Metadata)
	} else {
		builder.ClearMetadata()
	}

	_, err := builder.Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrListingNotFound
		}
		return fmt.Errorf("failed to update listing: %w", err)
	}
	return nil
}

// Delete removes a listing (must be draft or archived).
func (s *EntListingService) Delete(ctx context.Context, id uuid.UUID) error {
	// First check the status
	l, err := s.client.Listing.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrListingNotFound
		}
		return fmt.Errorf("failed to get listing: %w", err)
	}

	if l.Status != listing.StatusDraft && l.Status != listing.StatusArchived {
		return fmt.Errorf("cannot delete listing with status %s", l.Status)
	}

	err = s.client.Listing.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete listing: %w", err)
	}
	return nil
}

// Publish publishes a listing to the marketplace.
func (s *EntListingService) Publish(ctx context.Context, id uuid.UUID) error {
	now := time.Now()
	updated, err := s.client.Listing.UpdateOneID(id).
		SetStatus(listing.StatusPublished).
		SetPublishedAt(now).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrListingNotFound
		}
		return fmt.Errorf("failed to publish listing: %w", err)
	}

	// Sync to authorization system
	if s.authzSync != nil {
		l := entListingToListing(updated)
		if err := s.authzSync.SyncListing(ctx, l); err != nil {
			return fmt.Errorf("failed to sync listing to authz: %w", err)
		}
	}

	return nil
}

// Archive archives a listing, removing it from the marketplace.
func (s *EntListingService) Archive(ctx context.Context, id uuid.UUID) error {
	_, err := s.client.Listing.UpdateOneID(id).
		SetStatus(listing.StatusArchived).
		Save(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrListingNotFound
		}
		return fmt.Errorf("failed to archive listing: %w", err)
	}
	return nil
}

// List retrieves listings with optional filters.
func (s *EntListingService) List(ctx context.Context, opts ListListingsOptions) ([]*Listing, error) {
	query := s.client.Listing.Query()

	if opts.Status != nil {
		query = query.Where(listing.StatusEQ(listing.Status(*opts.Status)))
	}
	if opts.ProductType != nil {
		query = query.Where(listing.ProductTypeEQ(*opts.ProductType))
	}
	if opts.CreatorOrgID != nil {
		query = query.Where(listing.CreatorOrgIDEQ(*opts.CreatorOrgID))
	}
	if opts.PublishedOnly {
		query = query.Where(listing.StatusEQ(listing.StatusPublished))
	}

	// Default ordering by created_at desc
	if opts.OrderBy == "" {
		query = query.Order(ent.Desc(listing.FieldCreatedAt))
	}

	if opts.Offset > 0 {
		query = query.Offset(opts.Offset)
	}
	if opts.Limit > 0 {
		query = query.Limit(opts.Limit)
	}

	entListings, err := query.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list listings: %w", err)
	}

	listings := make([]*Listing, len(entListings))
	for i, el := range entListings {
		listings[i] = entListingToListing(el)
	}
	return listings, nil
}

// ListByCreator retrieves all listings for a creator organization.
func (s *EntListingService) ListByCreator(ctx context.Context, creatorOrgID uuid.UUID) ([]*Listing, error) {
	return s.List(ctx, ListListingsOptions{
		CreatorOrgID: &creatorOrgID,
	})
}

// entListingToListing converts an Ent Listing to a marketplace.Listing.
func entListingToListing(el *ent.Listing) *Listing {
	l := &Listing{
		ID:           el.ID,
		CreatorOrgID: el.CreatorOrgID,
		OwnerID:      el.OwnerID,
		ProductType:  el.ProductType,
		Title:        el.Title,
		Description:  el.Description,
		PricingModel: PricingModel(el.PricingModel),
		PriceCents:   el.PriceCents,
		Currency:     el.Currency,
		Status:       ListingStatus(el.Status),
		CreatedAt:    el.CreatedAt,
		UpdatedAt:    el.UpdatedAt,
		PublishedAt:  el.PublishedAt,
	}

	if el.ProductID != nil {
		l.ProductID = *el.ProductID
	}
	if el.Metadata != nil {
		l.Metadata = el.Metadata
	}

	return l
}

// Ensure EntListingService implements ListingService.
var _ ListingService = (*EntListingService)(nil)
