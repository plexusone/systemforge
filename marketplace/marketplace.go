package marketplace

import (
	"github.com/plexusone/systemforge/identity/ent"
)

// EntService is the Ent-backed implementation of the marketplace Service interface.
type EntService struct {
	listings      *EntListingService
	licenses      *EntLicenseService
	subscriptions *EntSubscriptionService
}

// NewEntService creates a new Ent-backed marketplace service.
// The authzSync parameter is optional and can be nil if authorization sync is not needed.
func NewEntService(client *ent.Client, authzSync AuthzSyncer) *EntService {
	return &EntService{
		listings:      NewEntListingService(client, authzSync),
		licenses:      NewEntLicenseService(client, authzSync),
		subscriptions: NewEntSubscriptionService(client),
	}
}

// WithPublishGate makes publishing a paid listing require that gate allows
// its creator organization; see EntListingService.WithPublishGate.
func (s *EntService) WithPublishGate(gate PublishGate) *EntService {
	s.listings.WithPublishGate(gate)
	return s
}

// Listings returns the listing service.
func (s *EntService) Listings() ListingService {
	return s.listings
}

// Licenses returns the license service.
func (s *EntService) Licenses() LicenseService {
	return s.licenses
}

// Subscriptions returns the subscription service.
func (s *EntService) Subscriptions() SubscriptionService {
	return s.subscriptions
}

// Ensure EntService implements Service.
var _ Service = (*EntService)(nil)
