// Package marketplace provides a unified framework for two-sided marketplace
// applications including listings, licenses, and subscriptions.
package marketplace

import (
	"time"

	"github.com/google/uuid"
)

// PricingModel defines how a product is priced.
type PricingModel string

const (
	// PricingFree indicates no charge (may require attribution).
	PricingFree PricingModel = "free"

	// PricingOneTime indicates a single purchase for perpetual access.
	PricingOneTime PricingModel = "one_time"

	// PricingSubscription indicates recurring monthly/annual billing.
	PricingSubscription PricingModel = "subscription"

	// PricingPerSeat indicates per-user pricing within an organization.
	PricingPerSeat PricingModel = "per_seat"
)

// PricingModels returns all valid pricing models.
func PricingModels() []PricingModel {
	return []PricingModel{
		PricingFree,
		PricingOneTime,
		PricingSubscription,
		PricingPerSeat,
	}
}

// LicenseType defines the scope of a license.
type LicenseType string

const (
	// LicenseSeatBased grants access to a specific number of users.
	LicenseSeatBased LicenseType = "seat_based"

	// LicenseTeam grants access to all members of a team/group.
	LicenseTeam LicenseType = "team"

	// LicenseUnlimited grants unlimited access within an organization.
	LicenseUnlimited LicenseType = "unlimited"
)

// LicenseTypes returns all valid license types.
func LicenseTypes() []LicenseType {
	return []LicenseType{
		LicenseSeatBased,
		LicenseTeam,
		LicenseUnlimited,
	}
}

// ListingStatus represents the publication state of a listing.
type ListingStatus string

const (
	// ListingStatusDraft indicates the listing is being prepared.
	ListingStatusDraft ListingStatus = "draft"

	// ListingStatusPendingReview indicates the listing is awaiting approval.
	ListingStatusPendingReview ListingStatus = "pending_review"

	// ListingStatusPublished indicates the listing is live on the marketplace.
	ListingStatusPublished ListingStatus = "published"

	// ListingStatusArchived indicates the listing has been retired.
	ListingStatusArchived ListingStatus = "archived"
)

// ListingStatuses returns all valid listing statuses.
func ListingStatuses() []ListingStatus {
	return []ListingStatus{
		ListingStatusDraft,
		ListingStatusPendingReview,
		ListingStatusPublished,
		ListingStatusArchived,
	}
}

// SubscriptionStatus represents the state of a platform subscription.
type SubscriptionStatus string

const (
	// SubscriptionStatusActive indicates the subscription is current.
	SubscriptionStatusActive SubscriptionStatus = "active"

	// SubscriptionStatusTrialing indicates the subscription is in trial period.
	SubscriptionStatusTrialing SubscriptionStatus = "trialing"

	// SubscriptionStatusPastDue indicates payment has failed.
	SubscriptionStatusPastDue SubscriptionStatus = "past_due"

	// SubscriptionStatusCanceled indicates the subscription has been canceled.
	SubscriptionStatusCanceled SubscriptionStatus = "canceled"

	// SubscriptionStatusUnpaid indicates multiple payment failures.
	SubscriptionStatusUnpaid SubscriptionStatus = "unpaid"
)

// SubscriptionStatuses returns all valid subscription statuses.
func SubscriptionStatuses() []SubscriptionStatus {
	return []SubscriptionStatus{
		SubscriptionStatusActive,
		SubscriptionStatusTrialing,
		SubscriptionStatusPastDue,
		SubscriptionStatusCanceled,
		SubscriptionStatusUnpaid,
	}
}

// Listing represents a product available on the marketplace.
type Listing struct {
	// ID is the unique identifier for this listing.
	ID uuid.UUID `json:"id"`

	// CreatorOrgID is the organization that created this listing.
	CreatorOrgID uuid.UUID `json:"creatorOrgId"`

	// OwnerID is the principal who owns this listing.
	OwnerID uuid.UUID `json:"ownerId"`

	// ProductType identifies the type of product (app-specific).
	// Examples: "course", "dashboard_template", "data_connector"
	ProductType string `json:"productType"`

	// ProductID references the actual product in the app's domain.
	ProductID uuid.UUID `json:"productId"`

	// Application is the registered application identifier (an
	// authz.AppVocabulary application) that an active subscription or valid
	// license on this listing entitles its organization to. Empty when the
	// listing does not grant an application.
	Application string `json:"application,omitempty"`

	// Title is the display name for the listing.
	Title string `json:"title"`

	// Description is the detailed description of the product.
	Description string `json:"description,omitempty"`

	// PricingModel defines how the product is priced.
	PricingModel PricingModel `json:"pricingModel"`

	// PriceCents is the price in cents (0 for free).
	PriceCents int64 `json:"priceCents"`

	// Currency is the ISO 4217 currency code.
	Currency string `json:"currency"`

	// Status is the publication state.
	Status ListingStatus `json:"status"`

	// Metadata contains app-specific data.
	Metadata map[string]any `json:"metadata,omitempty"`

	// CreatedAt is when the listing was created.
	CreatedAt time.Time `json:"createdAt"`

	// UpdatedAt is when the listing was last modified.
	UpdatedAt time.Time `json:"updatedAt"`

	// PublishedAt is when the listing was published (nil if not published).
	PublishedAt *time.Time `json:"publishedAt,omitempty"`
}

// IsPublished returns true if the listing is live on the marketplace.
func (l *Listing) IsPublished() bool {
	return l.Status == ListingStatusPublished
}

// IsFree returns true if the listing has no cost.
func (l *Listing) IsFree() bool {
	return l.PricingModel == PricingFree || l.PriceCents == 0
}

// License represents an entitlement to use a product.
type License struct {
	// ID is the unique identifier for this license.
	ID uuid.UUID `json:"id"`

	// ListingID references the marketplace listing.
	ListingID uuid.UUID `json:"listingId"`

	// OrganizationID is the organization that holds this license.
	OrganizationID uuid.UUID `json:"organizationId"`

	// LicenseType defines the scope of access.
	LicenseType LicenseType `json:"licenseType"`

	// Seats is the number of allowed users (nil for unlimited).
	Seats *int `json:"seats,omitempty"`

	// UsedSeats is the current number of assigned users.
	UsedSeats int `json:"usedSeats"`

	// ValidFrom is when the license becomes active.
	ValidFrom time.Time `json:"validFrom"`

	// ValidUntil is when the license expires (nil for perpetual).
	ValidUntil *time.Time `json:"validUntil,omitempty"`

	// StripeSubscriptionID is the Stripe subscription (for recurring).
	StripeSubscriptionID *string `json:"stripeSubscriptionId,omitempty"`

	// PurchasedBy is the principal who purchased this license.
	PurchasedBy uuid.UUID `json:"purchasedBy"`

	// CreatedAt is when the license was created.
	CreatedAt time.Time `json:"createdAt"`

	// UpdatedAt is when the license was last modified.
	UpdatedAt time.Time `json:"updatedAt"`
}

// IsValid returns true if the license is currently valid.
func (l *License) IsValid() bool {
	now := time.Now()
	if now.Before(l.ValidFrom) {
		return false
	}
	if l.ValidUntil != nil && now.After(*l.ValidUntil) {
		return false
	}
	return true
}

// HasAvailableSeats returns true if seats are available for assignment.
func (l *License) HasAvailableSeats() bool {
	if l.Seats == nil {
		return true // Unlimited
	}
	return l.UsedSeats < *l.Seats
}

// SeatsRemaining returns the number of seats available.
// Returns -1 for unlimited licenses.
func (l *License) SeatsRemaining() int {
	if l.Seats == nil {
		return -1
	}
	return *l.Seats - l.UsedSeats
}

// SeatAssignment represents a user's assignment to a license seat.
type SeatAssignment struct {
	// ID is the unique identifier for this assignment.
	ID uuid.UUID `json:"id"`

	// LicenseID references the license.
	LicenseID uuid.UUID `json:"licenseId"`

	// PrincipalID is the user assigned to this seat.
	PrincipalID uuid.UUID `json:"principalId"`

	// AssignedBy is who made this assignment.
	AssignedBy uuid.UUID `json:"assignedBy"`

	// AssignedAt is when the seat was assigned.
	AssignedAt time.Time `json:"assignedAt"`
}

// Subscription represents a platform-level subscription for an organization.
type Subscription struct {
	// ID is the unique identifier for this subscription.
	ID uuid.UUID `json:"id"`

	// OrganizationID is the subscribing organization.
	OrganizationID uuid.UUID `json:"organizationId"`

	// ListingID is the listing this subscription is for. It is nil for the
	// organization-wide platform subscription, of which an organization
	// has at most one; it may hold one subscription per listing.
	ListingID *uuid.UUID `json:"listingId,omitempty"`

	// PlanTier is the subscription plan name.
	PlanTier string `json:"planTier"`

	// Status is the subscription state.
	Status SubscriptionStatus `json:"status"`

	// CurrentPeriodStart is when the current billing period began.
	CurrentPeriodStart time.Time `json:"currentPeriodStart"`

	// CurrentPeriodEnd is when the current billing period ends.
	CurrentPeriodEnd time.Time `json:"currentPeriodEnd"`

	// StripeSubscriptionID is the Stripe subscription ID.
	StripeSubscriptionID string `json:"stripeSubscriptionId"`

	// StripeCustomerID is the Stripe customer ID.
	StripeCustomerID string `json:"stripeCustomerId"`

	// CancelAtPeriodEnd indicates if subscription will cancel at period end.
	CancelAtPeriodEnd bool `json:"cancelAtPeriodEnd"`

	// CreatedAt is when the subscription was created.
	CreatedAt time.Time `json:"createdAt"`

	// UpdatedAt is when the subscription was last modified.
	UpdatedAt time.Time `json:"updatedAt"`
}

// IsActive returns true if the subscription is currently active.
func (s *Subscription) IsActive() bool {
	return s.Status == SubscriptionStatusActive || s.Status == SubscriptionStatusTrialing
}

// IsInTrial returns true if the subscription is in trial period.
func (s *Subscription) IsInTrial() bool {
	return s.Status == SubscriptionStatusTrialing
}

// DaysRemaining returns the days until the current period ends.
func (s *Subscription) DaysRemaining() int {
	remaining := time.Until(s.CurrentPeriodEnd)
	if remaining < 0 {
		return 0
	}
	return int(remaining.Hours() / 24)
}

// PlanTier constants for common subscription tiers.
const (
	PlanTierFree       = "free"
	PlanTierStarter    = "starter"
	PlanTierPro        = "pro"
	PlanTierEnterprise = "enterprise"
)

// PlanTiers returns all standard plan tiers.
func PlanTiers() []string {
	return []string{
		PlanTierFree,
		PlanTierStarter,
		PlanTierPro,
		PlanTierEnterprise,
	}
}

// RevenueShare defines the revenue split for marketplace sales.
type RevenueShare struct {
	// CreatorPercent is the percentage going to the creator (0-100).
	CreatorPercent int `json:"creatorPercent"`

	// PlatformPercent is the percentage going to the platform (0-100).
	PlatformPercent int `json:"platformPercent"`
}

// DefaultRevenueShare returns the default revenue split (70/30).
func DefaultRevenueShare() RevenueShare {
	return RevenueShare{
		CreatorPercent:  70,
		PlatformPercent: 30,
	}
}

// Validate checks if the revenue share adds up to 100%.
func (r RevenueShare) Validate() error {
	if r.CreatorPercent+r.PlatformPercent != 100 {
		return ErrInvalidRevenueShare
	}
	if r.CreatorPercent < 0 || r.PlatformPercent < 0 {
		return ErrInvalidRevenueShare
	}
	return nil
}
