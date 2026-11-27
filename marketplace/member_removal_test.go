package marketplace

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
)

type removalFixture struct {
	client           *ent.Client
	licenses         *EntLicenseService
	orgID, listingID uuid.UUID
	licenseID        uuid.UUID
	otherLicenseID   uuid.UUID
	leaving, staying uuid.UUID
	otherOnly        uuid.UUID
}

// newRemovalFixture is an organization with a three-seat license, held by a
// member who will leave and one who stays. The leaving member also holds a seat
// on another organization's license of the same listing.
func newRemovalFixture(t *testing.T, ctx context.Context) removalFixture {
	t.Helper()
	return newRemovalFixtureOn(t, ctx, newLicenseTestClient(t))
}

func newRemovalFixtureOn(t *testing.T, ctx context.Context, client *ent.Client) removalFixture {
	t.Helper()
	f := removalFixture{client: client, licenses: NewEntLicenseService(client, nil)}
	var ownerID uuid.UUID
	f.orgID, ownerID, f.listingID = createTestLicenseFixtures(t, ctx, client, NewEntListingService(client, nil))
	other, err := client.Organization.Create().
		SetName("Other Org").
		SetSlug("other-removal-" + uuid.NewString()[:8]).
		Save(ctx)
	if err != nil {
		t.Fatalf("failed to create org: %v", err)
	}
	seats := 3
	grant := func(orgID uuid.UUID) uuid.UUID {
		l := &License{
			ID:             uuid.New(),
			ListingID:      f.listingID,
			OrganizationID: orgID,
			LicenseType:    LicenseSeatBased,
			Seats:          &seats,
			ValidFrom:      time.Now().Add(-time.Hour),
			PurchasedBy:    ownerID,
		}
		if err := f.licenses.Grant(ctx, l); err != nil {
			t.Fatalf("Grant() error = %v", err)
		}
		return l.ID
	}
	f.licenseID, f.otherLicenseID = grant(f.orgID), grant(other.ID)
	person := func(orgID uuid.UUID) uuid.UUID {
		p, err := client.Principal.Create().
			SetType(principal.TypeHuman).
			SetIdentifier(uuid.NewString()).
			SetDisplayName("Member").
			Save(ctx)
		if err != nil {
			t.Fatalf("failed to create principal: %v", err)
		}
		addMember(t, ctx, client, p.ID, orgID, true)
		return p.ID
	}
	f.leaving, f.staying, f.otherOnly = person(f.orgID), person(f.orgID), person(other.ID)
	addMember(t, ctx, client, f.leaving, other.ID, true)
	for _, a := range []struct{ license, principal uuid.UUID }{
		{f.licenseID, f.leaving},
		{f.licenseID, f.staying},
		{f.otherLicenseID, f.leaving},
	} {
		if err := f.licenses.AssignSeat(ctx, &SeatAssignment{
			ID: uuid.New(), LicenseID: a.license, PrincipalID: a.principal, AssignedBy: ownerID,
		}); err != nil {
			t.Fatalf("AssignSeat() error = %v", err)
		}
	}
	return f
}

// seatsOn returns the used-seat count and the holders of a license.
func (f removalFixture) seatsOn(t *testing.T, ctx context.Context, licenseID uuid.UUID) (int, map[uuid.UUID]bool) {
	t.Helper()
	l, err := f.client.License.Get(ctx, licenseID)
	if err != nil {
		t.Fatalf("failed to get license: %v", err)
	}
	seats, err := l.QuerySeatAssignments().All(ctx)
	if err != nil {
		t.Fatalf("failed to list seats: %v", err)
	}
	holders := map[uuid.UUID]bool{}
	for _, s := range seats {
		holders[s.PrincipalID] = true
	}
	return l.UsedSeats, holders
}

func TestRemoveMemberReleasesSeats(t *testing.T) {
	ctx := context.Background()
	f := newRemovalFixture(t, ctx)

	if err := organization.NewService(f.client).RemoveMember(ctx, f.orgID, f.leaving); err != nil {
		t.Fatalf("RemoveMember() error = %v", err)
	}

	used, holders := f.seatsOn(t, ctx, f.licenseID)
	if used != 1 || holders[f.leaving] || !holders[f.staying] {
		t.Errorf("license: used = %d, holders = %v; want only the remaining member", used, holders)
	}
	used, holders = f.seatsOn(t, ctx, f.otherLicenseID)
	if used != 1 || !holders[f.leaving] {
		t.Errorf("other organization's license: used = %d, holders = %v; want it unchanged", used, holders)
	}
}

type seatGraph struct {
	removed []uuid.UUID
	err     error
}

func (g *seatGraph) SyncSeatUnassignment(_ context.Context, licenseID, _ uuid.UUID) error {
	g.removed = append(g.removed, licenseID)
	return g.err
}

func TestRemoveMemberRemovesSeatsFromGraph(t *testing.T) {
	ctx := context.Background()
	f := newRemovalFixture(t, ctx)
	graph := &seatGraph{}

	svc := organization.NewService(f.client, organization.WithSeatSyncer(graph))
	if err := svc.RemoveMember(ctx, f.orgID, f.leaving); err != nil {
		t.Fatalf("RemoveMember() error = %v", err)
	}
	if !slices.Equal(graph.removed, []uuid.UUID{f.licenseID}) {
		t.Errorf("removed from graph = %v, want %v", graph.removed, f.licenseID)
	}
}

// If the graph refuses, nothing is removed, so the call can be retried.
func TestRemoveMemberKeepsSeatWhenGraphRefuses(t *testing.T) {
	ctx := context.Background()
	f := newRemovalFixture(t, ctx)
	refused := errors.New("graph unavailable")

	svc := organization.NewService(f.client, organization.WithSeatSyncer(&seatGraph{err: refused}))
	if err := svc.RemoveMember(ctx, f.orgID, f.leaving); !errors.Is(err, refused) {
		t.Fatalf("RemoveMember() error = %v, want %v", err, refused)
	}
	used, holders := f.seatsOn(t, ctx, f.licenseID)
	if used != 2 || !holders[f.leaving] {
		t.Errorf("license: used = %d, holders = %v; want both seats kept", used, holders)
	}
	if _, err := svc.GetMembership(ctx, f.orgID, f.leaving); err != nil {
		t.Errorf("membership was removed: %v", err)
	}
}
