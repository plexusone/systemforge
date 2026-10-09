package marketplace

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/organization"
)

func TestEntitlementSource(t *testing.T) {
	client := newLicenseTestClient(t)
	listingSvc := NewEntListingService(client, nil)
	licenses := NewEntLicenseService(client, nil)
	subs := NewEntSubscriptionService(client)
	ctx := context.Background()
	source := EntitlementSource(subs, licenses)

	orgID, principalID, listingID := createTestLicenseFixtures(t, ctx, client, listingSvc)

	got, err := source(ctx, orgID)
	if err != nil {
		t.Fatalf("source with nothing: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("entitlements with nothing = %+v, want none", got)
	}

	if err := licenses.Grant(ctx, &License{
		ID: uuid.New(), ListingID: listingID, OrganizationID: orgID,
		LicenseType: LicenseUnlimited, ValidFrom: time.Now().Add(-time.Hour), PurchasedBy: principalID,
	}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if err := subs.Create(ctx, &Subscription{
		ID: uuid.New(), OrganizationID: orgID, PlanTier: "pro", Status: SubscriptionStatusActive,
		CurrentPeriodStart: time.Now(), CurrentPeriodEnd: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Create subscription: %v", err)
	}

	got, err = source(ctx, orgID)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	var sawSub, sawLicense bool
	for _, e := range got {
		switch e.Source {
		case organization.EntitlementSourceSubscription:
			sawSub = e.Tier == "pro" && e.ValidUntil != nil
		case organization.EntitlementSourceLicense:
			sawLicense = e.ListingID == listingID.String() && e.Tier == string(LicenseUnlimited)
		}
	}
	if len(got) != 2 || !sawSub || !sawLicense {
		t.Errorf("entitlements = %+v, want a pro subscription and an unlimited license", got)
	}
}
