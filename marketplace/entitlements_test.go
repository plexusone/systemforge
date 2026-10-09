package marketplace

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/organization"
)

type entFixture struct {
	client      *ent.Client
	listings    *EntListingService
	licenses    *EntLicenseService
	subs        *EntSubscriptionService
	orgID       uuid.UUID
	principalID uuid.UUID
	listingID   uuid.UUID
}

func newEntFixture(t *testing.T) *entFixture {
	t.Helper()
	client := newLicenseTestClient(t)
	f := &entFixture{
		client:   client,
		listings: NewEntListingService(client, nil),
		licenses: NewEntLicenseService(client, nil),
		subs:     NewEntSubscriptionService(client),
	}
	f.orgID, f.principalID, f.listingID = createTestLicenseFixtures(t, context.Background(), client, f.listings)
	return f
}

// newListing adds a listing that grants application.
func (f *entFixture) newListing(t *testing.T, application string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if err := f.listings.Create(context.Background(), &Listing{
		ID: id, CreatorOrgID: f.orgID, OwnerID: f.principalID, ProductType: "app",
		Title: "App " + application, PricingModel: PricingFree, Currency: "USD", Application: application,
	}); err != nil {
		t.Fatalf("create listing: %v", err)
	}
	return id
}

func (f *entFixture) grantLicense(t *testing.T, listingID uuid.UUID, lt LicenseType, seats *int) {
	t.Helper()
	if err := f.licenses.Grant(context.Background(), &License{
		ID: uuid.New(), ListingID: listingID, OrganizationID: f.orgID, LicenseType: lt, Seats: seats,
		ValidFrom: time.Now().Add(-time.Hour), PurchasedBy: f.principalID,
	}); err != nil {
		t.Fatalf("grant license: %v", err)
	}
}

func TestEntitlementSource(t *testing.T) {
	f := newEntFixture(t)
	ctx := context.Background()
	source := EntitlementSource(f.subs, f.licenses, f.listings)

	got, err := source(ctx, f.orgID)
	if err != nil {
		t.Fatalf("source with nothing: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("entitlements with nothing = %+v, want none", got)
	}

	f.grantLicense(t, f.listingID, LicenseUnlimited, nil)
	if err := f.subs.Create(ctx, &Subscription{
		ID: uuid.New(), OrganizationID: f.orgID, PlanTier: "pro", Status: SubscriptionStatusActive,
		CurrentPeriodStart: time.Now(), CurrentPeriodEnd: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("Create subscription: %v", err)
	}

	got, err = source(ctx, f.orgID)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	var sawSub, sawLicense bool
	for _, e := range got {
		switch e.Source {
		case organization.EntitlementSourceSubscription:
			sawSub = e.Tier == "pro" && e.ValidUntil != nil && e.Application == ""
		case organization.EntitlementSourceLicense:
			sawLicense = e.ListingID == f.listingID.String() && e.Tier == string(LicenseUnlimited) && e.Application == ""
		}
	}
	if len(got) != 2 || !sawSub || !sawLicense {
		t.Errorf("entitlements = %+v, want a pro subscription and an unlimited license, neither granting an application", got)
	}
}

func TestEntitlementsMapListingsToApplications(t *testing.T) {
	f := newEntFixture(t)
	ctx := context.Background()
	notes := f.newListing(t, "notes")
	boards := f.newListing(t, "boards")
	f.grantLicense(t, notes, LicenseUnlimited, nil)
	if err := f.subs.Create(ctx, &Subscription{
		ID: uuid.New(), OrganizationID: f.orgID, ListingID: &boards, PlanTier: "pro", Status: SubscriptionStatusTrialing,
		CurrentPeriodStart: time.Now(), CurrentPeriodEnd: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("create listing subscription: %v", err)
	}
	// A platform subscription coexists with the per-listing one.
	if err := f.subs.Create(ctx, &Subscription{
		ID: uuid.New(), OrganizationID: f.orgID, PlanTier: "free", Status: SubscriptionStatusActive,
		CurrentPeriodStart: time.Now(), CurrentPeriodEnd: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("create platform subscription: %v", err)
	}
	// A canceled subscription and a second platform subscription are refused or inert.
	if err := f.subs.Create(ctx, &Subscription{
		ID: uuid.New(), OrganizationID: f.orgID, PlanTier: "free", Status: SubscriptionStatusActive,
		CurrentPeriodStart: time.Now(), CurrentPeriodEnd: time.Now().Add(24 * time.Hour),
	}); err == nil {
		t.Error("second platform subscription accepted, want a constraint error")
	}
	if err := f.subs.Create(ctx, &Subscription{
		ID: uuid.New(), OrganizationID: f.orgID, ListingID: &boards, PlanTier: "pro", Status: SubscriptionStatusActive,
		CurrentPeriodStart: time.Now(), CurrentPeriodEnd: time.Now().Add(24 * time.Hour),
	}); err == nil {
		t.Error("second subscription for one listing accepted, want a constraint error")
	}

	platform, err := f.subs.GetByOrg(ctx, f.orgID)
	if err != nil || platform.ListingID != nil || platform.PlanTier != "free" {
		t.Fatalf("GetByOrg = %+v, %v; want the platform subscription", platform, err)
	}

	got, err := EntitlementSource(f.subs, f.licenses, f.listings, WithDefaultEntitlements("wiki"))(ctx, f.orgID)
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	apps := map[string]string{}
	for _, e := range got {
		if e.Application != "" {
			apps[e.Application] = e.Source
		}
	}
	want := map[string]string{
		"notes":  organization.EntitlementSourceLicense,
		"boards": organization.EntitlementSourceSubscription,
		"wiki":   organization.EntitlementSourceDefault,
	}
	if len(apps) != len(want) {
		t.Fatalf("applications = %v, want %v", apps, want)
	}
	for app, src := range want {
		if apps[app] != src {
			t.Errorf("application %q from %q, want %q", app, apps[app], src)
		}
	}
}

func TestEntitlementsExcludeInactive(t *testing.T) {
	f := newEntFixture(t)
	ctx := context.Background()
	notes := f.newListing(t, "notes")
	boards := f.newListing(t, "boards")
	if err := f.licenses.Grant(ctx, &License{
		ID: uuid.New(), ListingID: notes, OrganizationID: f.orgID, LicenseType: LicenseUnlimited,
		ValidFrom: time.Now().Add(-48 * time.Hour), ValidUntil: ptr(time.Now().Add(-time.Hour)), PurchasedBy: f.principalID,
	}); err != nil {
		t.Fatalf("grant expired license: %v", err)
	}
	if err := f.subs.Create(ctx, &Subscription{
		ID: uuid.New(), OrganizationID: f.orgID, ListingID: &boards, PlanTier: "pro", Status: SubscriptionStatusCanceled,
		CurrentPeriodStart: time.Now(), CurrentPeriodEnd: time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	got, err := EntitlementSource(f.subs, f.licenses, f.listings)(ctx, f.orgID)
	if err != nil || len(got) != 0 {
		t.Errorf("entitlements = %+v, %v; want none from an expired license and a canceled subscription", got, err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestApproleOptionsSeatAccounting(t *testing.T) {
	f := newEntFixture(t)
	ctx := context.Background()
	notes := f.newListing(t, "notes")
	boards := f.newListing(t, "boards")
	f.grantLicense(t, notes, LicenseSeatBased, ptr(2))
	f.grantLicense(t, f.newListing(t, "notes"), LicenseSeatBased, ptr(3))
	f.grantLicense(t, boards, LicenseSeatBased, ptr(1))
	f.grantLicense(t, f.newListing(t, "wiki"), LicenseUnlimited, nil)

	src := EntitlementSource(f.subs, f.licenses, f.listings, WithDefaultEntitlements("boards"))
	got := grantsFrom(mustEntitlements(t, ctx, src, f.orgID))
	if g, ok := got["notes"]; !ok || g.SeatLimit == nil || *g.SeatLimit != 5 {
		t.Errorf("notes grant = %+v, want 5 seats from two licenses", g)
	}
	if g, ok := got["boards"]; !ok || g.SeatLimit != nil {
		t.Errorf("boards grant = %+v, want unlimited because a default entitlement covers it", g)
	}
	if g, ok := got["wiki"]; !ok || g.SeatLimit != nil {
		t.Errorf("wiki grant = %+v, want unlimited", g)
	}
	if _, ok := got["other"]; ok {
		t.Error("unregistered application granted")
	}
}

func mustEntitlements(t *testing.T, ctx context.Context, src organization.EntitlementSource, orgID uuid.UUID) []organization.Entitlement {
	t.Helper()
	list, err := src(ctx, orgID)
	if err != nil {
		t.Fatalf("entitlements: %v", err)
	}
	return list
}

type ladderVocab struct{ app string }

func (v ladderVocab) App() string { return v.app }
func (ladderVocab) Roles() authz.RolePermissions {
	return authz.RolePermissions{"viewer": {"item.read"}, "admin": {"item.read", "app.admin"}}
}
func (ladderVocab) Hierarchy() authz.RoleHierarchy {
	return authz.RoleHierarchy{"viewer": 10, "admin": 40}
}
func (v ladderVocab) Scopes() []string    { return []string{v.app + ":admin"} }
func (ladderVocab) SpiceDBSchema() string { return "" }

func TestApproleServiceUsesMarketplaceEntitlements(t *testing.T) {
	f := newEntFixture(t)
	ctx := context.Background()
	reg := authz.NewVocabularyRegistry()
	for _, app := range []string{"notes", "boards"} {
		if err := reg.Register(ladderVocab{app: app}); err != nil {
			t.Fatalf("register %s: %v", app, err)
		}
	}
	// The licensing fixture's organization has no owner membership, so add one member.
	if _, err := f.client.PrincipalMembership.Create().
		SetPrincipalID(f.principalID).SetOrganizationID(f.orgID).SetRole("member").Save(ctx); err != nil {
		t.Fatalf("membership: %v", err)
	}
	f.grantLicense(t, f.newListing(t, "notes"), LicenseUnlimited, nil)

	svc := approle.NewService(f.client, reg, ApproleOptions(EntitlementSource(f.subs, f.licenses, f.listings))...)
	in := approle.AssignInput{OrganizationID: f.orgID, PrincipalID: f.principalID, Application: "notes", Role: "viewer", AssignedBy: f.principalID}
	if _, err := svc.Assign(ctx, in); err != nil {
		t.Errorf("assign in licensed application: %v", err)
	}
	in.Application = "boards"
	if _, err := svc.Assign(ctx, in); err == nil || !strings.Contains(err.Error(), "not entitled") {
		t.Errorf("assign in unlicensed application = %v, want not entitled", err)
	}
}

func TestWarnIfNoEntitlements(t *testing.T) {
	f := newEntFixture(t)
	ctx := context.Background()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	if warned, err := WarnIfNoEntitlements(ctx, logger, f.listings, nil); err != nil || warned {
		t.Errorf("no applications registered: warned=%v err=%v, want quiet", warned, err)
	}
	if warned, err := WarnIfNoEntitlements(ctx, logger, f.listings, []string{"notes"}); err != nil || !warned {
		t.Errorf("nothing entitles: warned=%v err=%v, want a warning", warned, err)
	}
	if !strings.Contains(buf.String(), "WARN") {
		t.Errorf("log = %q, want a warning", buf.String())
	}
	if warned, _ := WarnIfNoEntitlements(ctx, logger, f.listings, []string{"notes"}, WithDefaultEntitlements("notes")); warned {
		t.Error("warned despite a default entitlement")
	}
	f.newListing(t, "notes")
	if warned, _ := WarnIfNoEntitlements(ctx, logger, f.listings, []string{"notes"}); warned {
		t.Error("warned despite a listing that names an application")
	}
}
