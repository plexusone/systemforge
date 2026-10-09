package organization

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Entitlement sources.
const (
	EntitlementSourceSubscription = "subscription"
	EntitlementSourceLicense      = "license"
	// EntitlementSourceDefault marks an application every organization of
	// the deployment is entitled to, by configuration.
	EntitlementSourceDefault = "default"
)

// Entitlement summarizes one thing an organization may use, derived from
// its marketplace subscriptions and licenses. An organization has no
// single plan: what it may use is the set of its entitlements.
type Entitlement struct {
	// Source is EntitlementSourceSubscription, EntitlementSourceLicense or
	// EntitlementSourceDefault.
	Source string `json:"source"`
	// Application is the registered application identifier the entitlement
	// grants, when it grants one. A platform-wide subscription has none.
	Application string `json:"application,omitempty"`
	// Seats caps the principals who may hold a role in Application, for a
	// seat-licensed entitlement. Nil means unlimited.
	Seats *int `json:"seats,omitempty"`
	// ListingID is the marketplace listing a license is for. It is empty
	// for a subscription, which is organization-wide.
	ListingID string `json:"listing_id,omitempty"`
	// Tier is the subscription's plan tier or the license type.
	Tier string `json:"tier,omitempty"`
	// ValidUntil is when the entitlement ends, when it does.
	ValidUntil *time.Time `json:"valid_until,omitempty"`
}

// EntitlementSource lists the active entitlements of an organization.
// marketplace.EntitlementSource builds one from the marketplace services.
type EntitlementSource func(ctx context.Context, organizationID uuid.UUID) ([]Entitlement, error)

// entitlementsFor returns the organization's entitlements, or an empty
// list when no source is configured.
func (a *API) entitlementsFor(ctx context.Context, organizationID uuid.UUID) ([]Entitlement, error) {
	if a.config.Entitlements == nil {
		return []Entitlement{}, nil
	}
	list, err := a.config.Entitlements(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	if list == nil {
		list = []Entitlement{}
	}
	return list, nil
}

// orgResponse builds the API representation of an organization with its
// entitlements.
func (a *API) orgResponse(ctx context.Context, org *Organization) (*OrgResponse, error) {
	resp := orgToResponse(org)
	ents, err := a.entitlementsFor(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	resp.Entitlements = ents
	return resp, nil
}
