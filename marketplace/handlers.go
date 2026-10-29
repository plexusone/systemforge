package marketplace

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/internal/apierror"
)

// API handles marketplace HTTP endpoints.
type API struct {
	huma     huma.API
	config   APIConfig
	listings ListingService
	licenses LicenseService

	caller CallerResolver
	authz  authz.Authorizer
}

// APIConfig holds API configuration.
type APIConfig struct {
	// BasePath is the API base path (e.g., "/api/v1").
	BasePath string
}

// NewAPI creates a new marketplace API handler. Operations act for the
// authenticated caller (see WithCallerResolver). Checkout is served by
// package billing.
func NewAPI(humaAPI huma.API, cfg APIConfig, svc Service, opts ...APIOption) *API {
	api := &API{
		huma:     humaAPI,
		config:   cfg,
		listings: svc.Listings(),
		licenses: svc.Licenses(),
		caller:   RequestPrincipalCaller,
	}
	for _, opt := range opts {
		opt(api)
	}
	api.registerEndpoints()
	return api
}

// registerEndpoints registers all marketplace endpoints.
func (a *API) registerEndpoints() {
	a.registerListingEndpoints()
	a.registerLicenseEndpoints()
}

// --- Listing Types ---

// ListingResponse is the API representation of a listing.
type ListingResponse struct {
	ID           string         `json:"id"`
	CreatorOrgID string         `json:"creator_org_id"`
	OwnerID      string         `json:"owner_id"`
	ProductType  string         `json:"product_type"`
	ProductID    *string        `json:"product_id,omitempty"`
	Application  string         `json:"application,omitempty"`
	Title        string         `json:"title"`
	Description  string         `json:"description,omitempty"`
	PricingModel string         `json:"pricing_model"`
	PriceCents   int64          `json:"price_cents"`
	Currency     string         `json:"currency"`
	Status       string         `json:"status"`
	Metadata     map[string]any `json:"metadata,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	PublishedAt  *time.Time     `json:"published_at,omitempty"`
}

func listingToResponse(l *Listing) *ListingResponse {
	resp := &ListingResponse{
		ID:           l.ID.String(),
		CreatorOrgID: l.CreatorOrgID.String(),
		OwnerID:      l.OwnerID.String(),
		ProductType:  l.ProductType,
		Application:  l.Application,
		Title:        l.Title,
		Description:  l.Description,
		PricingModel: string(l.PricingModel),
		PriceCents:   l.PriceCents,
		Currency:     l.Currency,
		Status:       string(l.Status),
		Metadata:     l.Metadata,
		CreatedAt:    l.CreatedAt,
		UpdatedAt:    l.UpdatedAt,
		PublishedAt:  l.PublishedAt,
	}
	if l.ProductID != uuid.Nil {
		s := l.ProductID.String()
		resp.ProductID = &s
	}
	return resp
}

// CreateListingInput is the request for creating a listing.
type CreateListingInput struct {
	Body struct {
		CreatorOrgID string         `json:"creator_org_id" required:"true" format:"uuid"`
		OwnerID      string         `json:"owner_id,omitempty" required:"false" format:"uuid" doc:"Deprecated: the owner is the authenticated caller; when present it must equal the caller"`
		ProductType  string         `json:"product_type" required:"true" minLength:"1" maxLength:"50"`
		ProductID    *string        `json:"product_id,omitempty" format:"uuid"`
		Title        string         `json:"title" required:"true" minLength:"1" maxLength:"200"`
		Description  string         `json:"description,omitempty" maxLength:"5000"`
		PricingModel string         `json:"pricing_model" required:"true" enum:"free,one_time,subscription,per_seat"`
		PriceCents   int64          `json:"price_cents" minimum:"0"`
		Currency     string         `json:"currency" required:"true" minLength:"3" maxLength:"3" default:"USD"`
		Metadata     map[string]any `json:"metadata,omitempty"`
	}
}

// CreateListingOutput is the response for creating a listing.
type CreateListingOutput struct {
	Body *ListingResponse
}

// GetListingInput is the request for getting a listing.
type GetListingInput struct {
	ID string `path:"id" format:"uuid"`
}

// GetListingOutput is the response for getting a listing.
type GetListingOutput struct {
	Body *ListingResponse
}

// UpdateListingInput is the request for updating a listing.
type UpdateListingInput struct {
	ID   string `path:"id" format:"uuid"`
	Body struct {
		Title        *string        `json:"title,omitempty" maxLength:"200"`
		Description  *string        `json:"description,omitempty" maxLength:"5000"`
		PricingModel *string        `json:"pricing_model,omitempty" enum:"free,one_time,subscription,per_seat"`
		PriceCents   *int64         `json:"price_cents,omitempty" minimum:"0"`
		Currency     *string        `json:"currency,omitempty" minLength:"3" maxLength:"3"`
		ProductID    *string        `json:"product_id,omitempty" format:"uuid"`
		Metadata     map[string]any `json:"metadata,omitempty"`
	}
}

// UpdateListingOutput is the response for updating a listing.
type UpdateListingOutput struct {
	Body *ListingResponse
}

// DeleteListingInput is the request for deleting a listing.
type DeleteListingInput struct {
	ID string `path:"id" format:"uuid"`
}

// PublishListingInput is the request for publishing a listing.
type PublishListingInput struct {
	ID string `path:"id" format:"uuid"`
}

// PublishListingOutput is the response for publishing a listing.
type PublishListingOutput struct {
	Body *ListingResponse
}

// ArchiveListingInput is the request for archiving a listing.
type ArchiveListingInput struct {
	ID string `path:"id" format:"uuid"`
}

// ArchiveListingOutput is the response for archiving a listing.
type ArchiveListingOutput struct {
	Body *ListingResponse
}

// ListListingsInput is the request for listing listings.
type ListListingsInput struct {
	// Huma does not support pointer parameters; an empty value means
	// the filter is not applied.
	Status       string `query:"status" enum:"draft,pending_review,published,archived"`
	ProductType  string `query:"product_type"`
	CreatorOrgID string `query:"creator_org_id" format:"uuid"`
	Published    bool   `query:"published"`
	Limit        int    `query:"limit" default:"20" minimum:"1" maximum:"100"`
	Offset       int    `query:"offset" default:"0" minimum:"0"`
}

// ListListingsOutput is the response for listing listings.
type ListListingsOutput struct {
	Body struct {
		Listings []*ListingResponse `json:"listings"`
		Total    int                `json:"total"`
	}
}

func (a *API) registerListingEndpoints() {
	basePath := a.config.BasePath

	huma.Register(a.huma, huma.Operation{
		OperationID:   "createListing",
		Method:        http.MethodPost,
		Path:          basePath + "/listings",
		Summary:       "Create a listing",
		Description:   "Creates a new marketplace listing in draft status",
		Tags:          []string{"Listings"},
		DefaultStatus: http.StatusCreated,
	}, a.createListing)

	huma.Register(a.huma, huma.Operation{
		OperationID:   "getListing",
		Method:        http.MethodGet,
		Path:          basePath + "/listings/{id}",
		Summary:       "Get a listing",
		Description:   "Returns a listing by ID",
		Tags:          []string{"Listings"},
		DefaultStatus: http.StatusOK,
	}, a.getListing)

	huma.Register(a.huma, huma.Operation{
		OperationID:   "updateListing",
		Method:        http.MethodPatch,
		Path:          basePath + "/listings/{id}",
		Summary:       "Update a listing",
		Description:   "Updates an existing listing",
		Tags:          []string{"Listings"},
		DefaultStatus: http.StatusOK,
	}, a.updateListing)

	huma.Register(a.huma, huma.Operation{
		OperationID:   "deleteListing",
		Method:        http.MethodDelete,
		Path:          basePath + "/listings/{id}",
		Summary:       "Delete a listing",
		Description:   "Deletes a listing (must be draft or archived)",
		Tags:          []string{"Listings"},
		DefaultStatus: http.StatusNoContent,
	}, a.deleteListing)

	huma.Register(a.huma, huma.Operation{
		OperationID:   "publishListing",
		Method:        http.MethodPost,
		Path:          basePath + "/listings/{id}/publish",
		Summary:       "Publish a listing",
		Description:   "Publishes a listing to the marketplace",
		Tags:          []string{"Listings"},
		DefaultStatus: http.StatusOK,
	}, a.publishListing)

	huma.Register(a.huma, huma.Operation{
		OperationID:   "archiveListing",
		Method:        http.MethodPost,
		Path:          basePath + "/listings/{id}/archive",
		Summary:       "Archive a listing",
		Description:   "Archives a listing, removing it from the marketplace",
		Tags:          []string{"Listings"},
		DefaultStatus: http.StatusOK,
	}, a.archiveListing)

	huma.Register(a.huma, huma.Operation{
		OperationID:   "listListings",
		Method:        http.MethodGet,
		Path:          basePath + "/listings",
		Summary:       "List listings",
		Description:   "Returns a list of listings with optional filtering",
		Tags:          []string{"Listings"},
		DefaultStatus: http.StatusOK,
	}, a.listListings)
}

func (a *API) createListing(ctx context.Context, input *CreateListingInput) (*CreateListingOutput, error) {
	creatorOrgID, err := uuid.Parse(input.Body.CreatorOrgID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid creator_org_id")
	}
	// The owner is the caller, who must be able to edit for the
	// organization the listing is sold under.
	ownerID, err := a.requireOrg(ctx, creatorOrgID, authz.PermOrgEdit)
	if err != nil {
		return nil, err
	}
	if input.Body.OwnerID != "" {
		claimed, err := uuid.Parse(input.Body.OwnerID)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid owner_id")
		}
		if claimed != ownerID {
			return nil, huma.Error403Forbidden("owner_id must be the authenticated caller")
		}
	}

	var productID uuid.UUID
	if input.Body.ProductID != nil {
		productID, err = uuid.Parse(*input.Body.ProductID)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid product_id")
		}
	}

	listing := &Listing{
		ID:           uuid.New(),
		CreatorOrgID: creatorOrgID,
		OwnerID:      ownerID,
		ProductType:  input.Body.ProductType,
		ProductID:    productID,
		Title:        input.Body.Title,
		Description:  input.Body.Description,
		PricingModel: PricingModel(input.Body.PricingModel),
		PriceCents:   input.Body.PriceCents,
		Currency:     input.Body.Currency,
		Metadata:     input.Body.Metadata,
	}

	if err := a.listings.Create(ctx, listing); err != nil {
		return nil, listingError(ctx, "marketplace: creating listing", err)
	}

	return &CreateListingOutput{Body: listingToResponse(listing)}, nil
}

func (a *API) getListing(ctx context.Context, input *GetListingInput) (*GetListingOutput, error) {
	id, err := uuid.Parse(input.ID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid listing ID")
	}

	listing, err := a.listings.Get(ctx, id)
	if err != nil {
		return nil, listingError(ctx, "marketplace: loading listing", err)
	}
	// Published listings are public; others are visible to their creator
	// organization only, and do not exist for anyone else.
	if !listing.IsPublished() {
		ok, err := a.canViewOrg(ctx, listing.CreatorOrgID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, huma.Error404NotFound("listing not found")
		}
	}

	return &GetListingOutput{Body: listingToResponse(listing)}, nil
}

func (a *API) updateListing(ctx context.Context, input *UpdateListingInput) (*UpdateListingOutput, error) {
	listing, err := a.listingFor(ctx, input.ID, authz.PermOrgEdit)
	if err != nil {
		return nil, err
	}
	id := listing.ID

	if input.Body.Title != nil {
		listing.Title = *input.Body.Title
	}
	if input.Body.Description != nil {
		listing.Description = *input.Body.Description
	}
	if input.Body.PricingModel != nil {
		listing.PricingModel = PricingModel(*input.Body.PricingModel)
	}
	if input.Body.PriceCents != nil {
		listing.PriceCents = *input.Body.PriceCents
	}
	if input.Body.Currency != nil {
		listing.Currency = *input.Body.Currency
	}
	if input.Body.ProductID != nil {
		productID, err := uuid.Parse(*input.Body.ProductID)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid product_id")
		}
		listing.ProductID = productID
	}
	if input.Body.Metadata != nil {
		listing.Metadata = input.Body.Metadata
	}

	if err := a.listings.Update(ctx, listing); err != nil {
		return nil, listingError(ctx, "marketplace: updating listing", err)
	}

	// Fetch updated listing
	updated, err := a.listings.Get(ctx, id)
	if err != nil {
		return nil, listingError(ctx, "marketplace: loading listing", err)
	}

	return &UpdateListingOutput{Body: listingToResponse(updated)}, nil
}

func (a *API) deleteListing(ctx context.Context, input *DeleteListingInput) (*struct{}, error) {
	listing, err := a.listingFor(ctx, input.ID, authz.PermOrgManage)
	if err != nil {
		return nil, err
	}

	if err := a.listings.Delete(ctx, listing.ID); err != nil {
		return nil, listingError(ctx, "marketplace: deleting listing", err)
	}

	return nil, nil
}

func (a *API) publishListing(ctx context.Context, input *PublishListingInput) (*PublishListingOutput, error) {
	current, err := a.listingFor(ctx, input.ID, authz.PermOrgManage)
	if err != nil {
		return nil, err
	}
	id := current.ID

	if err := a.listings.Publish(ctx, id); err != nil {
		return nil, listingError(ctx, "marketplace: publishing listing", err)
	}

	listing, err := a.listings.Get(ctx, id)
	if err != nil {
		return nil, listingError(ctx, "marketplace: loading listing", err)
	}

	return &PublishListingOutput{Body: listingToResponse(listing)}, nil
}

func (a *API) archiveListing(ctx context.Context, input *ArchiveListingInput) (*ArchiveListingOutput, error) {
	current, err := a.listingFor(ctx, input.ID, authz.PermOrgManage)
	if err != nil {
		return nil, err
	}
	id := current.ID

	if err := a.listings.Archive(ctx, id); err != nil {
		return nil, listingError(ctx, "marketplace: archiving listing", err)
	}

	listing, err := a.listings.Get(ctx, id)
	if err != nil {
		return nil, listingError(ctx, "marketplace: loading listing", err)
	}

	return &ArchiveListingOutput{Body: listingToResponse(listing)}, nil
}

func (a *API) listListings(ctx context.Context, input *ListListingsInput) (*ListListingsOutput, error) {
	opts := ListListingsOptions{
		Limit:  input.Limit,
		Offset: input.Offset,
	}

	if input.Status != "" {
		s := ListingStatus(input.Status)
		opts.Status = &s
	}
	if input.ProductType != "" {
		opts.ProductType = &input.ProductType
	}
	// Unpublished listings are listed only to members of the creator
	// organization the request filters on; everyone else sees published
	// listings.
	membersView := false
	if input.CreatorOrgID != "" {
		id, err := uuid.Parse(input.CreatorOrgID)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid creator_org_id")
		}
		opts.CreatorOrgID = &id
		if membersView, err = a.canViewOrg(ctx, id); err != nil {
			return nil, err
		}
	}
	if input.Published || !membersView {
		opts.PublishedOnly = true
		if opts.Status != nil && *opts.Status != ListingStatusPublished {
			output := &ListListingsOutput{}
			output.Body.Listings = []*ListingResponse{}
			return output, nil
		}
	}

	listings, err := a.listings.List(ctx, opts)
	if err != nil {
		return nil, apierror.Internal(ctx, nil, "marketplace: listing listings", err)
	}

	responses := make([]*ListingResponse, len(listings))
	for i, l := range listings {
		responses[i] = listingToResponse(l)
	}

	output := &ListListingsOutput{}
	output.Body.Listings = responses
	output.Body.Total = len(responses)

	return output, nil
}

// --- License Types ---

// LicenseResponse is the API representation of a license.
type LicenseResponse struct {
	ID                   string     `json:"id"`
	ListingID            string     `json:"listing_id"`
	OrganizationID       string     `json:"organization_id"`
	LicenseType          string     `json:"license_type"`
	Seats                *int       `json:"seats,omitempty"`
	UsedSeats            int        `json:"used_seats"`
	ValidFrom            time.Time  `json:"valid_from"`
	ValidUntil           *time.Time `json:"valid_until,omitempty"`
	StripeSubscriptionID *string    `json:"stripe_subscription_id,omitempty"`
	PurchasedBy          string     `json:"purchased_by"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

func licenseToResponse(l *License) *LicenseResponse {
	return &LicenseResponse{
		ID:                   l.ID.String(),
		ListingID:            l.ListingID.String(),
		OrganizationID:       l.OrganizationID.String(),
		LicenseType:          string(l.LicenseType),
		Seats:                l.Seats,
		UsedSeats:            l.UsedSeats,
		ValidFrom:            l.ValidFrom,
		ValidUntil:           l.ValidUntil,
		StripeSubscriptionID: l.StripeSubscriptionID,
		PurchasedBy:          l.PurchasedBy.String(),
		CreatedAt:            l.CreatedAt,
		UpdatedAt:            l.UpdatedAt,
	}
}

// SeatAssignmentResponse is the API representation of a seat assignment.
type SeatAssignmentResponse struct {
	ID          string    `json:"id"`
	LicenseID   string    `json:"license_id"`
	PrincipalID string    `json:"principal_id"`
	AssignedBy  string    `json:"assigned_by"`
	AssignedAt  time.Time `json:"assigned_at"`
}

func seatAssignmentToResponse(sa *SeatAssignment) *SeatAssignmentResponse {
	return &SeatAssignmentResponse{
		ID:          sa.ID.String(),
		LicenseID:   sa.LicenseID.String(),
		PrincipalID: sa.PrincipalID.String(),
		AssignedBy:  sa.AssignedBy.String(),
		AssignedAt:  sa.AssignedAt,
	}
}

// ListLicensesInput is the request for listing licenses.
type ListLicensesInput struct {
	OrganizationID string `query:"organization_id" required:"true" format:"uuid"`
}

// ListLicensesOutput is the response for listing licenses.
type ListLicensesOutput struct {
	Body struct {
		Licenses []*LicenseResponse `json:"licenses"`
	}
}

// GetLicenseInput is the request for getting a license.
type GetLicenseInput struct {
	ID string `path:"id" format:"uuid"`
}

// GetLicenseOutput is the response for getting a license.
type GetLicenseOutput struct {
	Body *LicenseResponse
}

// AssignSeatInput is the request for assigning a seat.
type AssignSeatInput struct {
	LicenseID string `path:"license_id" format:"uuid"`
	Body      struct {
		PrincipalID string `json:"principal_id" required:"true" format:"uuid"`
		AssignedBy  string `json:"assigned_by,omitempty" required:"false" format:"uuid" doc:"Deprecated: the assigner is the authenticated caller; when present it must equal the caller"`
	}
}

// AssignSeatOutput is the response for assigning a seat.
type AssignSeatOutput struct {
	Body *SeatAssignmentResponse
}

// UnassignSeatInput is the request for unassigning a seat.
type UnassignSeatInput struct {
	LicenseID   string `path:"license_id" format:"uuid"`
	PrincipalID string `path:"principal_id" format:"uuid"`
}

// ListSeatsInput is the request for listing seat assignments.
type ListSeatsInput struct {
	LicenseID string `path:"license_id" format:"uuid"`
}

// ListSeatsOutput is the response for listing seat assignments.
type ListSeatsOutput struct {
	Body struct {
		Seats          []*SeatAssignmentResponse `json:"seats"`
		TotalSeats     *int                      `json:"total_seats,omitempty"`
		UsedSeats      int                       `json:"used_seats"`
		AvailableSeats int                       `json:"available_seats"`
	}
}

func (a *API) registerLicenseEndpoints() {
	basePath := a.config.BasePath

	huma.Register(a.huma, huma.Operation{
		OperationID:   "listLicenses",
		Method:        http.MethodGet,
		Path:          basePath + "/licenses",
		Summary:       "List licenses",
		Description:   "Returns licenses for an organization",
		Tags:          []string{"Licenses"},
		DefaultStatus: http.StatusOK,
	}, a.listLicenses)

	huma.Register(a.huma, huma.Operation{
		OperationID:   "getLicense",
		Method:        http.MethodGet,
		Path:          basePath + "/licenses/{id}",
		Summary:       "Get a license",
		Description:   "Returns a license by ID",
		Tags:          []string{"Licenses"},
		DefaultStatus: http.StatusOK,
	}, a.getLicense)

	huma.Register(a.huma, huma.Operation{
		OperationID:   "assignSeat",
		Method:        http.MethodPost,
		Path:          basePath + "/licenses/{license_id}/seats",
		Summary:       "Assign a seat",
		Description:   "Assigns a user to a license seat",
		Tags:          []string{"Licenses"},
		DefaultStatus: http.StatusCreated,
	}, a.assignSeat)

	huma.Register(a.huma, huma.Operation{
		OperationID:   "unassignSeat",
		Method:        http.MethodDelete,
		Path:          basePath + "/licenses/{license_id}/seats/{principal_id}",
		Summary:       "Unassign a seat",
		Description:   "Removes a user from a license seat",
		Tags:          []string{"Licenses"},
		DefaultStatus: http.StatusNoContent,
	}, a.unassignSeat)

	huma.Register(a.huma, huma.Operation{
		OperationID:   "listSeats",
		Method:        http.MethodGet,
		Path:          basePath + "/licenses/{license_id}/seats",
		Summary:       "List seat assignments",
		Description:   "Returns all seat assignments for a license",
		Tags:          []string{"Licenses"},
		DefaultStatus: http.StatusOK,
	}, a.listSeats)
}

func (a *API) listLicenses(ctx context.Context, input *ListLicensesInput) (*ListLicensesOutput, error) {
	orgID, err := uuid.Parse(input.OrganizationID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid organization_id")
	}
	if _, err := a.requireOrg(ctx, orgID, authz.PermOrgView); err != nil {
		return nil, err
	}

	licenses, err := a.licenses.List(ctx, orgID)
	if err != nil {
		return nil, apierror.Internal(ctx, nil, "marketplace: listing licenses", err)
	}

	responses := make([]*LicenseResponse, len(licenses))
	for i, l := range licenses {
		responses[i] = licenseToResponse(l)
	}

	output := &ListLicensesOutput{}
	output.Body.Licenses = responses

	return output, nil
}

func (a *API) getLicense(ctx context.Context, input *GetLicenseInput) (*GetLicenseOutput, error) {
	license, _, err := a.licenseFor(ctx, input.ID, authz.PermOrgView)
	if err != nil {
		return nil, err
	}

	return &GetLicenseOutput{Body: licenseToResponse(license)}, nil
}

func (a *API) assignSeat(ctx context.Context, input *AssignSeatInput) (*AssignSeatOutput, error) {
	license, assignedBy, err := a.licenseFor(ctx, input.LicenseID, authz.PermOrgManage)
	if err != nil {
		return nil, err
	}
	licenseID := license.ID
	principalID, err := uuid.Parse(input.Body.PrincipalID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid principal_id")
	}
	if input.Body.AssignedBy != "" {
		claimed, err := uuid.Parse(input.Body.AssignedBy)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid assigned_by")
		}
		if claimed != assignedBy {
			return nil, huma.Error403Forbidden("assigned_by must be the authenticated caller")
		}
	}
	// Seats go to members of the licensed organization.
	member, err := a.canOrg(ctx, principalID, license.OrganizationID, authz.PermOrgView)
	if err != nil {
		return nil, err
	}
	if !member {
		return nil, huma.Error400BadRequest("principal is not a member of the licensed organization")
	}

	assignment := &SeatAssignment{
		ID:          uuid.New(),
		LicenseID:   licenseID,
		PrincipalID: principalID,
		AssignedBy:  assignedBy,
	}

	if err := a.licenses.AssignSeat(ctx, assignment); err != nil {
		if err == ErrLicenseNotFound {
			return nil, huma.Error404NotFound("license not found")
		}
		if err == ErrNoSeatsAvailable {
			return nil, huma.Error400BadRequest("no seats available")
		}
		if err == ErrSeatAlreadyAssigned {
			return nil, huma.Error400BadRequest("seat already assigned to this user")
		}
		return nil, apierror.Internal(ctx, nil, "marketplace: assigning seat", err)
	}

	return &AssignSeatOutput{Body: seatAssignmentToResponse(assignment)}, nil
}

func (a *API) unassignSeat(ctx context.Context, input *UnassignSeatInput) (*struct{}, error) {
	license, _, err := a.licenseFor(ctx, input.LicenseID, authz.PermOrgManage)
	if err != nil {
		return nil, err
	}
	licenseID := license.ID
	principalID, err := uuid.Parse(input.PrincipalID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid principal_id")
	}

	if err := a.licenses.UnassignSeat(ctx, licenseID, principalID); err != nil {
		if err == ErrLicenseNotFound {
			return nil, huma.Error404NotFound("license not found")
		}
		if err == ErrSeatNotAssigned {
			return nil, huma.Error404NotFound("seat not assigned")
		}
		return nil, apierror.Internal(ctx, nil, "marketplace: unassigning seat", err)
	}

	return nil, nil
}

func (a *API) listSeats(ctx context.Context, input *ListSeatsInput) (*ListSeatsOutput, error) {
	license, _, err := a.licenseFor(ctx, input.LicenseID, authz.PermOrgView)
	if err != nil {
		return nil, err
	}
	licenseID := license.ID

	assignments, err := a.licenses.ListSeatAssignments(ctx, licenseID)
	if err != nil {
		return nil, apierror.Internal(ctx, nil, "marketplace: listing seats", err)
	}

	responses := make([]*SeatAssignmentResponse, len(assignments))
	for i, sa := range assignments {
		responses[i] = seatAssignmentToResponse(sa)
	}

	output := &ListSeatsOutput{}
	output.Body.Seats = responses
	output.Body.TotalSeats = license.Seats
	output.Body.UsedSeats = license.UsedSeats
	if license.Seats != nil {
		output.Body.AvailableSeats = *license.Seats - license.UsedSeats
	} else {
		output.Body.AvailableSeats = -1 // Unlimited
	}

	return output, nil
}

// listingError maps a listing service error to an API error. The errors a
// client can act on get fixed messages; anything else is logged and
// answered with a generic 500, so database text never reaches the client.
func listingError(ctx context.Context, op string, err error) error {
	switch {
	case errors.Is(err, ErrListingNotFound):
		return huma.Error404NotFound("listing not found")
	case errors.Is(err, ErrSellerNotReady):
		return huma.Error409Conflict("the organization cannot take payments yet")
	case errors.Is(err, ErrInvalidListing):
		// The field name is the client's own input; the validator's
		// text is not passed on.
		var ve *ent.ValidationError
		if errors.As(err, &ve) && ve.Name != "" {
			return huma.Error400BadRequest(ErrInvalidListing.Error() + ": " + ve.Name)
		}
		return huma.Error400BadRequest(ErrInvalidListing.Error())
	case errors.Is(err, ErrListingNotDeletable):
		return huma.Error400BadRequest(ErrListingNotDeletable.Error())
	case errors.Is(err, ErrInvalidPricingModel):
		return huma.Error400BadRequest(ErrInvalidPricingModel.Error())
	}
	return apierror.Internal(ctx, nil, op, err)
}
