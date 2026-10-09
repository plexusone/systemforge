package marketplace

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/organization"
)

// EntitlementSource returns an organization.EntitlementSource that
// derives an organization's entitlements from its active subscription and
// its valid licenses. Either service may be nil to leave that source out.
func EntitlementSource(subs SubscriptionService, licenses LicenseService) organization.EntitlementSource {
	return func(ctx context.Context, orgID uuid.UUID) ([]organization.Entitlement, error) {
		out := []organization.Entitlement{}
		if subs != nil {
			sub, err := subs.GetByOrg(ctx, orgID)
			switch {
			case errors.Is(err, ErrSubscriptionNotFound):
			case err != nil:
				return nil, fmt.Errorf("entitlements: subscription: %w", err)
			case sub.IsActive():
				e := organization.Entitlement{
					Source: organization.EntitlementSourceSubscription,
					Tier:   sub.PlanTier,
				}
				if !sub.CurrentPeriodEnd.IsZero() {
					end := sub.CurrentPeriodEnd
					e.ValidUntil = &end
				}
				out = append(out, e)
			}
		}
		if licenses != nil {
			list, err := licenses.List(ctx, orgID)
			if err != nil {
				return nil, fmt.Errorf("entitlements: licenses: %w", err)
			}
			for _, l := range list {
				if !l.IsValid() {
					continue
				}
				out = append(out, organization.Entitlement{
					Source:     organization.EntitlementSourceLicense,
					ListingID:  l.ListingID.String(),
					Tier:       string(l.LicenseType),
					ValidUntil: l.ValidUntil,
				})
			}
		}
		return out, nil
	}
}
