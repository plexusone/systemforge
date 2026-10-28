package marketplace

import (
	"context"

	"github.com/google/uuid"
)

// ListingService provides operations for marketplace listings.
type ListingService interface {
	// Create creates a new listing in draft status.
	Create(ctx context.Context, listing *Listing) error

	// Get retrieves a listing by ID.
	Get(ctx context.Context, id uuid.UUID) (*Listing, error)

	// GetByProduct retrieves a listing by product type and ID.
	GetByProduct(ctx context.Context, productType string, productID uuid.UUID) (*Listing, error)

	// Update updates a listing's details.
	Update(ctx context.Context, listing *Listing) error

	// Delete removes a listing (must be draft or archived).
	Delete(ctx context.Context, id uuid.UUID) error

	// Publish publishes a listing to the marketplace.
	Publish(ctx context.Context, id uuid.UUID) error

	// Archive archives a listing, removing it from the marketplace.
	Archive(ctx context.Context, id uuid.UUID) error

	// List retrieves listings with optional filters.
	List(ctx context.Context, opts ListListingsOptions) ([]*Listing, error)

	// ListByCreator retrieves all listings for a creator organization.
	ListByCreator(ctx context.Context, creatorOrgID uuid.UUID) ([]*Listing, error)
}

// ListListingsOptions configures listing queries.
type ListListingsOptions struct {
	// Status filters by listing status.
	Status *ListingStatus

	// ProductType filters by product type.
	ProductType *string

	// CreatorOrgID filters by creator organization.
	CreatorOrgID *uuid.UUID

	// PublishedOnly returns only published listings.
	PublishedOnly bool

	// Limit is the maximum number of results.
	Limit int

	// Offset is the pagination offset.
	Offset int

	// OrderBy specifies the sort order.
	OrderBy string
}

// LicenseService provides operations for licenses and entitlements.
type LicenseService interface {
	// Grant creates a new license for an organization.
	Grant(ctx context.Context, license *License) error

	// Get retrieves a license by ID.
	Get(ctx context.Context, id uuid.UUID) (*License, error)

	// GetByListingAndOrg retrieves a license for a specific listing and organization.
	GetByListingAndOrg(ctx context.Context, listingID, orgID uuid.UUID) (*License, error)

	// GetByStripeSubscriptionID retrieves the license a Stripe
	// subscription pays for, or ErrLicenseNotFound.
	GetByStripeSubscriptionID(ctx context.Context, subscriptionID string) (*License, error)

	// Update updates a license's details.
	Update(ctx context.Context, license *License) error

	// Revoke revokes a license, removing access.
	Revoke(ctx context.Context, id uuid.UUID) error

	// Check checks if an organization has a valid license for a listing.
	Check(ctx context.Context, listingID, orgID uuid.UUID) (bool, error)

	// CheckPrincipal checks if a principal has access via license.
	CheckPrincipal(ctx context.Context, listingID, principalID uuid.UUID) (bool, error)

	// List retrieves licenses for an organization.
	List(ctx context.Context, orgID uuid.UUID) ([]*License, error)

	// ListByListing retrieves all licenses for a listing.
	ListByListing(ctx context.Context, listingID uuid.UUID) ([]*License, error)

	// AssignSeat assigns a user to a license seat.
	AssignSeat(ctx context.Context, assignment *SeatAssignment) error

	// UnassignSeat removes a user from a license seat.
	UnassignSeat(ctx context.Context, licenseID, principalID uuid.UUID) error

	// ListSeatAssignments retrieves all seat assignments for a license.
	ListSeatAssignments(ctx context.Context, licenseID uuid.UUID) ([]*SeatAssignment, error)
}

// SubscriptionService provides operations for platform subscriptions.
type SubscriptionService interface {
	// Create creates a new subscription.
	Create(ctx context.Context, sub *Subscription) error

	// Get retrieves a subscription by ID.
	Get(ctx context.Context, id uuid.UUID) (*Subscription, error)

	// GetByOrg retrieves the subscription for an organization.
	GetByOrg(ctx context.Context, orgID uuid.UUID) (*Subscription, error)

	// Update updates a subscription's details.
	Update(ctx context.Context, sub *Subscription) error

	// Cancel cancels a subscription at period end.
	Cancel(ctx context.Context, id uuid.UUID) error

	// CancelImmediately cancels a subscription immediately.
	CancelImmediately(ctx context.Context, id uuid.UUID) error

	// Reactivate reactivates a canceled subscription.
	Reactivate(ctx context.Context, id uuid.UUID) error

	// ChangePlan changes the subscription plan.
	ChangePlan(ctx context.Context, id uuid.UUID, newPlan string) error

	// IsActive checks if an organization has an active subscription.
	IsActive(ctx context.Context, orgID uuid.UUID) (bool, error)

	// GetPlanTier returns the current plan tier for an organization.
	GetPlanTier(ctx context.Context, orgID uuid.UUID) (string, error)
}

// SubscriptionLister is implemented by a SubscriptionService that can
// list every subscription of an organization, the platform subscription
// and those for individual listings. It is a separate interface so
// existing SubscriptionService implementers keep compiling; without it,
// only the platform subscription from GetByOrg is considered.
type SubscriptionLister interface {
	ListByOrg(ctx context.Context, orgID uuid.UUID) ([]*Subscription, error)
}

// CheckoutService provides operations for purchasing licenses.
type CheckoutService interface {
	// CreateCheckoutSession creates a Stripe checkout session for a listing.
	CreateCheckoutSession(ctx context.Context, req CheckoutRequest) (*CheckoutSession, error)

	// ProcessWebhook handles Stripe webhook events.
	ProcessWebhook(ctx context.Context, payload []byte, signature string) error
}

// CheckoutRequest contains parameters for creating a checkout session.
type CheckoutRequest struct {
	// ListingID is the listing to purchase.
	ListingID uuid.UUID

	// OrganizationID is the purchasing organization.
	OrganizationID uuid.UUID

	// PurchaserID is the principal making the purchase.
	PurchaserID uuid.UUID

	// Seats is the number of seats (for per-seat pricing).
	Seats *int

	// SuccessURL is the redirect URL on success.
	SuccessURL string

	// CancelURL is the redirect URL on cancel.
	CancelURL string
}

// CheckoutSession contains the result of creating a checkout session.
type CheckoutSession struct {
	// SessionID is the Stripe checkout session ID.
	SessionID string

	// URL is the checkout URL to redirect the user to.
	URL string
}

// PurchaserChecker reports whether a principal is managed: a human
// without an email whose managers control the account. Managed principals
// cannot purchase. identity/managedprincipal.Service implements it.
type PurchaserChecker interface {
	IsManaged(ctx context.Context, principalID uuid.UUID) (bool, error)
}

// PublishGate decides whether a creator organization may publish a paid
// listing: whether it can take payments. billing.SellerGate implements it
// from the seller's connected payment account.
type PublishGate interface {
	CanPublish(ctx context.Context, creatorOrgID uuid.UUID) (bool, error)
}

// AuthzSyncer syncs marketplace entities to the authorization system.
type AuthzSyncer interface {
	// SyncListing syncs a listing to the authorization system.
	SyncListing(ctx context.Context, listing *Listing) error

	// SyncLicense syncs a license grant to the authorization system.
	SyncLicense(ctx context.Context, license *License) error

	// SyncLicenseRevocation syncs a license revocation to the authorization system.
	SyncLicenseRevocation(ctx context.Context, license *License) error

	// SyncSeatAssignment syncs a seat assignment to the authorization system.
	SyncSeatAssignment(ctx context.Context, assignment *SeatAssignment) error

	// SyncSeatUnassignment syncs a seat removal to the authorization system.
	SyncSeatUnassignment(ctx context.Context, licenseID, principalID uuid.UUID) error
}

// Service combines all marketplace services.
type Service interface {
	Listings() ListingService
	Licenses() LicenseService
	Subscriptions() SubscriptionService
	Checkout() CheckoutService
}
