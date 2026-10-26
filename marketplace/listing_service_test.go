package marketplace

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"

	_ "github.com/mattn/go-sqlite3"
)

func newTestClient(t *testing.T) *ent.Client {
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Logf("failed to close client: %v", err)
		}
	})
	return client
}

func TestEntListingService_CreateAndGet(t *testing.T) {
	client := newTestClient(t)
	svc := NewEntListingService(client, nil)
	ctx := context.Background()

	// Create test organization and principal first
	org, err := client.Organization.Create().
		SetName("Test Org").
		SetSlug("test-org").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}

	principal, err := client.Principal.Create().
		SetType("human").
		SetIdentifier("test@example.com").
		SetDisplayName("Test User").
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create principal: %v", err)
	}

	// Create a listing
	listing := &Listing{
		ID:           uuid.New(),
		CreatorOrgID: org.ID,
		OwnerID:      principal.ID,
		ProductType:  "course",
		Title:        "Test Course",
		Description:  "A test course",
		PricingModel: PricingOneTime,
		PriceCents:   4999,
		Currency:     "USD",
	}

	err = svc.Create(ctx, listing)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Verify listing was created with draft status
	if listing.Status != ListingStatusDraft {
		t.Errorf("Status = %v, want %v", listing.Status, ListingStatusDraft)
	}

	// Get the listing
	got, err := svc.Get(ctx, listing.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if got.Title != listing.Title {
		t.Errorf("Title = %v, want %v", got.Title, listing.Title)
	}
	if got.PriceCents != listing.PriceCents {
		t.Errorf("PriceCents = %v, want %v", got.PriceCents, listing.PriceCents)
	}
}

func TestEntListingService_PublishAndArchive(t *testing.T) {
	client := newTestClient(t)
	svc := NewEntListingService(client, nil)
	ctx := context.Background()

	// Create test org and principal
	org, _ := client.Organization.Create().
		SetName("Test Org").
		SetSlug("test-org-2").
		Save(ctx)
	principal, _ := client.Principal.Create().
		SetType("human").
		SetIdentifier("test2@example.com").
		SetDisplayName("Test User 2").
		Save(ctx)

	// Create a listing
	listing := &Listing{
		ID:           uuid.New(),
		CreatorOrgID: org.ID,
		OwnerID:      principal.ID,
		ProductType:  "course",
		ProductID:    uuid.New(),
		Title:        "Publishable Course",
		PricingModel: PricingFree,
		Currency:     "USD",
	}
	if err := svc.Create(ctx, listing); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Publish
	if err := svc.Publish(ctx, listing.ID); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	got, _ := svc.Get(ctx, listing.ID)
	if got.Status != ListingStatusPublished {
		t.Errorf("Status = %v, want %v", got.Status, ListingStatusPublished)
	}
	if got.PublishedAt == nil {
		t.Error("PublishedAt should not be nil")
	}

	// Archive
	if err := svc.Archive(ctx, listing.ID); err != nil {
		t.Fatalf("Archive() error = %v", err)
	}

	got, _ = svc.Get(ctx, listing.ID)
	if got.Status != ListingStatusArchived {
		t.Errorf("Status = %v, want %v", got.Status, ListingStatusArchived)
	}
}

func TestEntListingService_List(t *testing.T) {
	client := newTestClient(t)
	svc := NewEntListingService(client, nil)
	ctx := context.Background()

	// Create test org and principal
	org, _ := client.Organization.Create().
		SetName("Test Org").
		SetSlug("test-org-3").
		Save(ctx)
	principal, _ := client.Principal.Create().
		SetType("human").
		SetIdentifier("test3@example.com").
		SetDisplayName("Test User 3").
		Save(ctx)

	// Create multiple listings
	for i := 0; i < 5; i++ {
		listing := &Listing{
			ID:           uuid.New(),
			CreatorOrgID: org.ID,
			OwnerID:      principal.ID,
			ProductType:  "course",
			Title:        "Course " + string(rune('A'+i)),
			PricingModel: PricingFree,
			Currency:     "USD",
		}
		if err := svc.Create(ctx, listing); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	// List all
	listings, err := svc.List(ctx, ListListingsOptions{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(listings) != 5 {
		t.Errorf("List() count = %v, want 5", len(listings))
	}

	// List by creator
	listings, err = svc.ListByCreator(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListByCreator() error = %v", err)
	}
	if len(listings) != 5 {
		t.Errorf("ListByCreator() count = %v, want 5", len(listings))
	}

	// List with limit
	listings, err = svc.List(ctx, ListListingsOptions{Limit: 3})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(listings) != 3 {
		t.Errorf("List(limit=3) count = %v, want 3", len(listings))
	}
}

func TestEntListingService_GetByProduct(t *testing.T) {
	client := newTestClient(t)
	svc := NewEntListingService(client, nil)
	ctx := context.Background()

	// Create test org and principal
	org, _ := client.Organization.Create().
		SetName("Test Org").
		SetSlug("test-org-4").
		Save(ctx)
	principal, _ := client.Principal.Create().
		SetType("human").
		SetIdentifier("test4@example.com").
		SetDisplayName("Test User 4").
		Save(ctx)

	productID := uuid.New()
	listing := &Listing{
		ID:           uuid.New(),
		CreatorOrgID: org.ID,
		OwnerID:      principal.ID,
		ProductType:  "dashboard",
		ProductID:    productID,
		Title:        "Dashboard Template",
		PricingModel: PricingSubscription,
		PriceCents:   999,
		Currency:     "USD",
	}
	if err := svc.Create(ctx, listing); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Get by product
	got, err := svc.GetByProduct(ctx, "dashboard", productID)
	if err != nil {
		t.Fatalf("GetByProduct() error = %v", err)
	}
	if got.ID != listing.ID {
		t.Errorf("ID = %v, want %v", got.ID, listing.ID)
	}

	// Get by non-existent product
	_, err = svc.GetByProduct(ctx, "dashboard", uuid.New())
	if err != ErrListingNotFound {
		t.Errorf("GetByProduct() error = %v, want %v", err, ErrListingNotFound)
	}
}

func TestEntListingService_Delete(t *testing.T) {
	client := newTestClient(t)
	svc := NewEntListingService(client, nil)
	ctx := context.Background()

	// Create test org and principal
	org, _ := client.Organization.Create().
		SetName("Test Org").
		SetSlug("test-org-5").
		Save(ctx)
	principal, _ := client.Principal.Create().
		SetType("human").
		SetIdentifier("test5@example.com").
		SetDisplayName("Test User 5").
		Save(ctx)

	// Create a draft listing
	listing := &Listing{
		ID:           uuid.New(),
		CreatorOrgID: org.ID,
		OwnerID:      principal.ID,
		ProductType:  "course",
		Title:        "To Be Deleted",
		PricingModel: PricingFree,
		Currency:     "USD",
	}
	if err := svc.Create(ctx, listing); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Delete draft listing (should succeed)
	if err := svc.Delete(ctx, listing.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify deleted
	_, err := svc.Get(ctx, listing.ID)
	if err != ErrListingNotFound {
		t.Errorf("Get() error = %v, want %v", err, ErrListingNotFound)
	}

	// Create and publish a listing
	listing2 := &Listing{
		ID:           uuid.New(),
		CreatorOrgID: org.ID,
		OwnerID:      principal.ID,
		ProductType:  "course",
		ProductID:    uuid.New(),
		Title:        "Published Listing",
		PricingModel: PricingFree,
		Currency:     "USD",
	}
	if err := svc.Create(ctx, listing2); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if err := svc.Publish(ctx, listing2.ID); err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	// Delete published listing (should fail)
	err = svc.Delete(ctx, listing2.ID)
	if err == nil {
		t.Error("Delete() should fail for published listing")
	}
}

func TestListingHelpers(t *testing.T) {
	// Test IsPublished
	l := &Listing{Status: ListingStatusPublished}
	if !l.IsPublished() {
		t.Error("IsPublished() = false, want true")
	}
	l.Status = ListingStatusDraft
	if l.IsPublished() {
		t.Error("IsPublished() = true, want false")
	}

	// Test IsFree
	l.PricingModel = PricingFree
	if !l.IsFree() {
		t.Error("IsFree() = false for PricingFree")
	}
	l.PricingModel = PricingOneTime
	l.PriceCents = 0
	if !l.IsFree() {
		t.Error("IsFree() = false for PriceCents=0")
	}
	l.PriceCents = 100
	if l.IsFree() {
		t.Error("IsFree() = true for PriceCents=100")
	}
}

func TestLicenseHelpers(t *testing.T) {
	now := time.Now()

	// Test IsValid
	l := &License{
		ValidFrom:  now.Add(-time.Hour),
		ValidUntil: nil,
	}
	if !l.IsValid() {
		t.Error("IsValid() = false for perpetual license")
	}

	future := now.Add(time.Hour)
	l.ValidUntil = &future
	if !l.IsValid() {
		t.Error("IsValid() = false for valid license")
	}

	past := now.Add(-time.Hour)
	l.ValidUntil = &past
	if l.IsValid() {
		t.Error("IsValid() = true for expired license")
	}

	// Test HasAvailableSeats
	l = &License{Seats: nil, UsedSeats: 0}
	if !l.HasAvailableSeats() {
		t.Error("HasAvailableSeats() = false for unlimited")
	}

	seats := 5
	l.Seats = &seats
	l.UsedSeats = 3
	if !l.HasAvailableSeats() {
		t.Error("HasAvailableSeats() = false with seats available")
	}

	l.UsedSeats = 5
	if l.HasAvailableSeats() {
		t.Error("HasAvailableSeats() = true with no seats")
	}

	// Test SeatsRemaining
	l.Seats = nil
	if l.SeatsRemaining() != -1 {
		t.Errorf("SeatsRemaining() = %d, want -1", l.SeatsRemaining())
	}

	l.Seats = &seats
	l.UsedSeats = 2
	if l.SeatsRemaining() != 3 {
		t.Errorf("SeatsRemaining() = %d, want 3", l.SeatsRemaining())
	}
}

func TestSubscriptionHelpers(t *testing.T) {
	// Test IsActive
	s := &Subscription{Status: SubscriptionStatusActive}
	if !s.IsActive() {
		t.Error("IsActive() = false for active subscription")
	}

	s.Status = SubscriptionStatusTrialing
	if !s.IsActive() {
		t.Error("IsActive() = false for trialing subscription")
	}

	s.Status = SubscriptionStatusCanceled
	if s.IsActive() {
		t.Error("IsActive() = true for canceled subscription")
	}

	// Test IsInTrial
	s.Status = SubscriptionStatusTrialing
	if !s.IsInTrial() {
		t.Error("IsInTrial() = false for trialing subscription")
	}

	s.Status = SubscriptionStatusActive
	if s.IsInTrial() {
		t.Error("IsInTrial() = true for active subscription")
	}

	// Test DaysRemaining
	s.CurrentPeriodEnd = time.Now().Add(24 * time.Hour * 10)
	days := s.DaysRemaining()
	if days < 9 || days > 11 {
		t.Errorf("DaysRemaining() = %d, want ~10", days)
	}

	s.CurrentPeriodEnd = time.Now().Add(-time.Hour)
	if s.DaysRemaining() != 0 {
		t.Errorf("DaysRemaining() = %d, want 0 for past date", s.DaysRemaining())
	}
}

// ValidUntil is exclusive: a license suspended by setting ValidUntil to the
// current time is invalid at that same instant, on clocks too coarse to
// have moved on.
func TestLicenseValidAtBoundaries(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	l := &License{ValidFrom: start, ValidUntil: &end}
	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"before ValidFrom", start.Add(-time.Nanosecond), false},
		{"at ValidFrom", start, true},
		{"just before ValidUntil", end.Add(-time.Nanosecond), true},
		{"at ValidUntil", end, false},
		{"after ValidUntil", end.Add(time.Nanosecond), false},
	}
	for _, tt := range tests {
		if got := l.validAt(tt.at); got != tt.want {
			t.Errorf("%s: validAt = %v, want %v", tt.name, got, tt.want)
		}
	}
}
