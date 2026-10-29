package marketplace

import "errors"

// Sentinel errors for marketplace operations.
var (
	// ErrListingNotFound is returned when a listing cannot be found.
	ErrListingNotFound = errors.New("listing not found")

	// ErrInvalidListing is returned when a listing's fields fail
	// validation.
	ErrInvalidListing = errors.New("invalid listing")

	// ErrListingNotDeletable is returned when deleting a listing that is
	// neither a draft nor archived.
	ErrListingNotDeletable = errors.New("only a draft or archived listing can be deleted")

	// ErrListingNotPublished is returned when accessing an unpublished listing.
	ErrListingNotPublished = errors.New("listing not published")

	// ErrLicenseNotFound is returned when a license cannot be found.
	ErrLicenseNotFound = errors.New("license not found")

	// ErrLicenseExpired is returned when a license has expired.
	ErrLicenseExpired = errors.New("license expired")

	// ErrLicenseNotYetValid is returned when a license hasn't started.
	ErrLicenseNotYetValid = errors.New("license not yet valid")

	// ErrNoSeatsAvailable is returned when all seats are assigned.
	ErrNoSeatsAvailable = errors.New("no seats available")

	// ErrSeatAlreadyAssigned is returned when a user already has a seat.
	ErrSeatAlreadyAssigned = errors.New("seat already assigned to this user")

	// ErrSeatNotAssigned is returned when trying to unassign a non-existent seat.
	ErrSeatNotAssigned = errors.New("seat not assigned to this user")

	// ErrSubscriptionNotFound is returned when a subscription cannot be found.
	ErrSubscriptionNotFound = errors.New("subscription not found")

	// ErrSubscriptionInactive is returned when a subscription is not active.
	ErrSubscriptionInactive = errors.New("subscription not active")

	// ErrInvalidRevenueShare is returned when revenue share doesn't add to 100%.
	ErrInvalidRevenueShare = errors.New("revenue share must add up to 100%")

	// ErrInvalidPricingModel is returned for unknown pricing models.
	ErrInvalidPricingModel = errors.New("invalid pricing model")

	// ErrInvalidLicenseType is returned for unknown license types.
	ErrInvalidLicenseType = errors.New("invalid license type")

	// ErrAlreadyLicensed is returned when an org already has a license.
	ErrAlreadyLicensed = errors.New("organization already licensed for this listing")

	// ErrManagedPurchaser is returned when a managed principal (a human
	// without an email, ADR-005) tries to purchase; billing is a guardian's
	// action.
	ErrManagedPurchaser = errors.New("managed principals cannot purchase")

	// ErrCannotPurchaseOwnListing is returned when a creator tries to purchase their own listing.
	ErrCannotPurchaseOwnListing = errors.New("cannot purchase your own listing")

	// ErrSellerNotReady is returned when a paid listing is published by an
	// organization that cannot take payments yet.
	ErrSellerNotReady = errors.New("seller cannot take payments")

	// ErrPaymentRequired is returned when payment is required but not provided.
	ErrPaymentRequired = errors.New("payment required")

	// ErrPaymentFailed is returned when payment processing fails.
	ErrPaymentFailed = errors.New("payment failed")
)
