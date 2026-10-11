package marketplace

import (
	"regexp"
	"testing"
	"time"

	"github.com/authzed/spicedb/pkg/schemadsl/compiler"
	"github.com/authzed/spicedb/pkg/schemadsl/input"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/plexusone/systemforge/authz"
)

func TestListing_IsPublished(t *testing.T) {
	tests := []struct {
		name   string
		status ListingStatus
		want   bool
	}{
		{"draft", ListingStatusDraft, false},
		{"pending", ListingStatusPendingReview, false},
		{"published", ListingStatusPublished, true},
		{"archived", ListingStatusArchived, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Listing{Status: tt.status}
			assert.Equal(t, tt.want, l.IsPublished())
		})
	}
}

func TestListing_IsFree(t *testing.T) {
	tests := []struct {
		name         string
		pricingModel PricingModel
		priceCents   int64
		want         bool
	}{
		{"free model", PricingFree, 0, true},
		{"free model with price", PricingFree, 100, true},
		{"one-time zero", PricingOneTime, 0, true},
		{"one-time paid", PricingOneTime, 999, false},
		{"subscription", PricingSubscription, 2999, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Listing{
				PricingModel: tt.pricingModel,
				PriceCents:   tt.priceCents,
			}
			assert.Equal(t, tt.want, l.IsFree())
		})
	}
}

func TestLicense_IsValid(t *testing.T) {
	now := time.Now()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	tests := []struct {
		name       string
		validFrom  time.Time
		validUntil *time.Time
		want       bool
	}{
		{"valid perpetual", past, nil, true},
		{"valid with end", past, &future, true},
		{"not yet valid", future, nil, false},
		{"expired", past, &past, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &License{
				ValidFrom:  tt.validFrom,
				ValidUntil: tt.validUntil,
			}
			assert.Equal(t, tt.want, l.IsValid())
		})
	}
}

func TestLicense_HasAvailableSeats(t *testing.T) {
	seats5 := 5

	tests := []struct {
		name      string
		seats     *int
		usedSeats int
		want      bool
	}{
		{"unlimited", nil, 100, true},
		{"seats available", &seats5, 3, true},
		{"no seats", &seats5, 5, false},
		{"over limit", &seats5, 6, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &License{
				Seats:     tt.seats,
				UsedSeats: tt.usedSeats,
			}
			assert.Equal(t, tt.want, l.HasAvailableSeats())
		})
	}
}

func TestLicense_SeatsRemaining(t *testing.T) {
	seats5 := 5

	tests := []struct {
		name      string
		seats     *int
		usedSeats int
		want      int
	}{
		{"unlimited", nil, 100, -1},
		{"3 remaining", &seats5, 2, 3},
		{"none remaining", &seats5, 5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &License{
				Seats:     tt.seats,
				UsedSeats: tt.usedSeats,
			}
			assert.Equal(t, tt.want, l.SeatsRemaining())
		})
	}
}

func TestSubscription_IsActive(t *testing.T) {
	tests := []struct {
		name   string
		status SubscriptionStatus
		want   bool
	}{
		{"active", SubscriptionStatusActive, true},
		{"trialing", SubscriptionStatusTrialing, true},
		{"past due", SubscriptionStatusPastDue, false},
		{"canceled", SubscriptionStatusCanceled, false},
		{"unpaid", SubscriptionStatusUnpaid, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Subscription{Status: tt.status}
			assert.Equal(t, tt.want, s.IsActive())
		})
	}
}

func TestSubscription_DaysRemaining(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		periodEnd  time.Time
		wantApprox int
	}{
		{"7 days", now.Add(7 * 24 * time.Hour), 7},
		{"0 days", now, 0},
		{"past", now.Add(-24 * time.Hour), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Subscription{CurrentPeriodEnd: tt.periodEnd}
			got := s.DaysRemaining()
			// Allow +/- 1 day variance for timing
			assert.InDelta(t, tt.wantApprox, got, 1)
		})
	}
}

func TestRevenueShare_Validate(t *testing.T) {
	tests := []struct {
		name            string
		creatorPercent  int
		platformPercent int
		wantErr         error
	}{
		{"valid 70/30", 70, 30, nil},
		{"valid 80/20", 80, 20, nil},
		{"invalid total", 60, 30, ErrInvalidRevenueShare},
		{"negative creator", -10, 110, ErrInvalidRevenueShare},
		{"negative platform", 110, -10, ErrInvalidRevenueShare},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := RevenueShare{
				CreatorPercent:  tt.creatorPercent,
				PlatformPercent: tt.platformPercent,
			}
			err := rs.Validate()
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDefaultRevenueShare(t *testing.T) {
	rs := DefaultRevenueShare()
	assert.Equal(t, 70, rs.CreatorPercent)
	assert.Equal(t, 30, rs.PlatformPercent)
	assert.NoError(t, rs.Validate())
}

func TestPricingModels(t *testing.T) {
	models := PricingModels()
	assert.Len(t, models, 4)
	assert.Contains(t, models, PricingFree)
	assert.Contains(t, models, PricingOneTime)
	assert.Contains(t, models, PricingSubscription)
	assert.Contains(t, models, PricingPerSeat)
}

func TestLicenseTypes(t *testing.T) {
	types := LicenseTypes()
	assert.Len(t, types, 3)
	assert.Contains(t, types, LicenseSeatBased)
	assert.Contains(t, types, LicenseTeam)
	assert.Contains(t, types, LicenseUnlimited)
}

func TestListingStatuses(t *testing.T) {
	statuses := ListingStatuses()
	assert.Len(t, statuses, 4)
	assert.Contains(t, statuses, ListingStatusDraft)
	assert.Contains(t, statuses, ListingStatusPendingReview)
	assert.Contains(t, statuses, ListingStatusPublished)
	assert.Contains(t, statuses, ListingStatusArchived)
}

func TestSubscriptionStatuses(t *testing.T) {
	statuses := SubscriptionStatuses()
	assert.Len(t, statuses, 5)
	assert.Contains(t, statuses, SubscriptionStatusActive)
	assert.Contains(t, statuses, SubscriptionStatusTrialing)
	assert.Contains(t, statuses, SubscriptionStatusPastDue)
	assert.Contains(t, statuses, SubscriptionStatusCanceled)
	assert.Contains(t, statuses, SubscriptionStatusUnpaid)
}

func TestPlanTiers(t *testing.T) {
	tiers := PlanTiers()
	assert.Len(t, tiers, 4)
	assert.Contains(t, tiers, PlanTierFree)
	assert.Contains(t, tiers, PlanTierStarter)
	assert.Contains(t, tiers, PlanTierPro)
	assert.Contains(t, tiers, PlanTierEnterprise)
}

func TestMarketplaceSchema(t *testing.T) {
	// Verify schema is embedded and non-empty
	assert.NotEmpty(t, MarketplaceSchema)
	assert.Contains(t, MarketplaceSchema, "definition marketplace_org")
	assert.Contains(t, MarketplaceSchema, "definition creator_org")
	assert.Contains(t, MarketplaceSchema, "definition listing")
	assert.Contains(t, MarketplaceSchema, "definition license")
	assert.Contains(t, MarketplaceSchema, "definition subscription")
}

func TestMergeSchema(t *testing.T) {
	appSchema := `
definition course {
    relation tenant: creator_org
    relation listing: listing
    permission view = listing->view
}
`
	merged := MergeSchema(appSchema)
	assert.Contains(t, merged, "definition principal")
	assert.Contains(t, merged, "definition marketplace_org")
	assert.Contains(t, merged, "definition course")
	assertSchemaCompiles(t, merged)
}

// assertSchemaCompiles compiles a composed schema with SpiceDB's own
// compiler, so unknown references and duplicate definitions fail here
// rather than when a deployment writes the schema.
func assertSchemaCompiles(t *testing.T, schema string) {
	t.Helper()
	if _, err := compiler.Compile(compiler.InputSchema{Source: input.Source("marketplace"), SchemaString: schema}, compiler.AllowUnprefixedObjectType()); err != nil {
		t.Fatalf("composed schema does not compile: %v", err)
	}
}

// TestMarketplaceSchemaComposesWithBase checks the fragment against the
// base schema: it compiles after it, redefines none of its definitions,
// and attaches through the marketplace_org facet.
func TestMarketplaceSchemaComposesWithBase(t *testing.T) {
	assertSchemaCompiles(t, MergeSchema(""))

	definition := regexp.MustCompile(`(?m)^definition\s+(\w+)`)
	base := map[string]bool{}
	for _, m := range definition.FindAllStringSubmatch(authz.BaseSpiceDBSchema, -1) {
		base[m[1]] = true
	}
	for _, m := range definition.FindAllStringSubmatch(MarketplaceSchema, -1) {
		assert.Falsef(t, base[m[1]], "marketplace.zed redefines the base definition %q", m[1])
	}
	assert.Regexp(t, `(?s)definition marketplace_org \{.*relation org: organization`, MarketplaceSchema)
}

func TestListingJSON(t *testing.T) {
	listing := &Listing{
		ID:           uuid.New(),
		CreatorOrgID: uuid.New(),
		OwnerID:      uuid.New(),
		ProductType:  "course",
		ProductID:    uuid.New(),
		Title:        "Test Course",
		PricingModel: PricingOneTime,
		PriceCents:   2999,
		Currency:     "USD",
		Status:       ListingStatusDraft,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Verify basic fields are set correctly
	assert.NotEqual(t, uuid.Nil, listing.ID)
	assert.Equal(t, "Test Course", listing.Title)
	assert.Equal(t, int64(2999), listing.PriceCents)
}
