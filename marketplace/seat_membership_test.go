package marketplace

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/principalmembership"
)

// AssignSeat refuses a principal that does not belong to the licensed
// organization, and reserves nothing.
func TestAssignSeatNeedsMembership(t *testing.T) {
	ctx := context.Background()
	f := newRemovalFixture(t, ctx)
	for name, principalID := range map[string]uuid.UUID{
		"unknown principal":              uuid.New(),
		"member of another organization": f.otherOnly,
	} {
		err := f.licenses.AssignSeat(ctx, &SeatAssignment{
			ID: uuid.New(), LicenseID: f.licenseID, PrincipalID: principalID, AssignedBy: f.staying,
		})
		if !errors.Is(err, ErrNotOrganizationMember) {
			t.Errorf("%s: AssignSeat() error = %v, want %v", name, err, ErrNotOrganizationMember)
		}
	}
	if used, holders := f.seatsOn(t, ctx, f.licenseID); used != 2 || len(holders) != 2 {
		t.Errorf("license: used = %d, holders = %v; want the two members", used, holders)
	}
}

// A seat left behind by a membership that ended grants nothing.
func TestCheckPrincipalIgnoresSeatOfFormerMember(t *testing.T) {
	ctx := context.Background()
	f := newRemovalFixture(t, ctx)
	check := func() bool {
		t.Helper()
		ok, err := f.licenses.CheckPrincipal(ctx, f.listingID, f.staying)
		if err != nil {
			t.Fatalf("CheckPrincipal() error = %v", err)
		}
		return ok
	}
	if !check() {
		t.Fatal("CheckPrincipal() = false for a member with a seat")
	}
	if _, err := f.client.PrincipalMembership.Delete().
		Where(principalmembership.PrincipalID(f.staying)).
		Exec(ctx); err != nil {
		t.Fatalf("failed to delete membership: %v", err)
	}
	if check() {
		t.Error("CheckPrincipal() = true for a former member's seat")
	}
}

// The graph write after an assignment rereads the rows, so it does not restore
// a seat that ended since the assignment committed.
func TestSeatGraphWriteSkipsEndedSeat(t *testing.T) {
	ctx := context.Background()
	f := newRemovalFixture(t, ctx)
	graph := &recordingSyncer{}
	svc := NewEntLicenseService(f.client, graph)
	seat := &SeatAssignment{LicenseID: f.licenseID, PrincipalID: f.staying}

	if err := svc.writeSeatToGraph(ctx, f.orgID, seat); err != nil {
		t.Fatalf("writeSeatToGraph() error = %v", err)
	}
	if graph.assigned != 1 {
		t.Fatalf("graph writes for a held seat = %d, want 1", graph.assigned)
	}
	if err := svc.UnassignSeat(ctx, f.licenseID, f.staying); err != nil {
		t.Fatalf("UnassignSeat() error = %v", err)
	}
	if err := svc.writeSeatToGraph(ctx, f.orgID, seat); err != nil {
		t.Fatalf("writeSeatToGraph() error = %v", err)
	}
	if graph.assigned != 1 {
		t.Errorf("graph writes after the seat ended = %d, want 1", graph.assigned)
	}
}

// recordingSyncer counts seat writes and accepts everything else.
type recordingSyncer struct {
	assigned    int
	unassignErr error
}

func (r *recordingSyncer) SyncListing(context.Context, *Listing) error           { return nil }
func (r *recordingSyncer) SyncLicense(context.Context, *License) error           { return nil }
func (r *recordingSyncer) SyncLicenseRevocation(context.Context, *License) error { return nil }
func (r *recordingSyncer) SyncSeatUnassignment(context.Context, uuid.UUID, uuid.UUID) error {
	return r.unassignErr
}

func (r *recordingSyncer) SyncSeatAssignment(context.Context, *SeatAssignment) error {
	r.assigned++
	return nil
}

// Belonging means an active principal in an active organization, in a role that
// holds organization permissions.
func TestSeatAccessNeedsActiveStanding(t *testing.T) {
	for name, end := range map[string]func(t *testing.T, ctx context.Context, f removalFixture){
		"deactivated principal": func(t *testing.T, ctx context.Context, f removalFixture) {
			if err := f.client.Principal.UpdateOneID(f.staying).SetActive(false).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		},
		"deactivated organization": func(t *testing.T, ctx context.Context, f removalFixture) {
			if err := f.client.Organization.UpdateOneID(f.orgID).SetActive(false).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		},
		"collaborator": func(t *testing.T, ctx context.Context, f removalFixture) {
			if err := f.client.PrincipalMembership.Update().
				Where(principalmembership.PrincipalID(f.staying)).
				SetRole("collaborator").
				Exec(ctx); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f := newRemovalFixture(t, ctx)
			end(t, ctx, f)
			ok, err := f.licenses.CheckPrincipal(ctx, f.listingID, f.staying)
			if err != nil {
				t.Fatalf("CheckPrincipal() error = %v", err)
			}
			if ok {
				t.Error("CheckPrincipal() = true, want false")
			}
			if err := f.licenses.UnassignSeat(ctx, f.licenseID, f.staying); err != nil {
				t.Fatalf("UnassignSeat() error = %v", err)
			}
			err = f.licenses.AssignSeat(ctx, &SeatAssignment{
				ID: uuid.New(), LicenseID: f.licenseID, PrincipalID: f.staying, AssignedBy: f.leaving,
			})
			if !errors.Is(err, ErrNotOrganizationMember) {
				t.Errorf("AssignSeat() error = %v, want %v", err, ErrNotOrganizationMember)
			}
		})
	}
}

// If the graph refuses, the seat stays, so the unassignment can be retried.
func TestUnassignSeatKeepsSeatWhenGraphRefuses(t *testing.T) {
	ctx := context.Background()
	f := newRemovalFixture(t, ctx)
	refused := errors.New("graph unavailable")
	graph := &recordingSyncer{unassignErr: refused}
	svc := NewEntLicenseService(f.client, graph)

	if err := svc.UnassignSeat(ctx, f.licenseID, f.staying); !errors.Is(err, refused) {
		t.Fatalf("UnassignSeat() error = %v, want %v", err, refused)
	}
	if used, holders := f.seatsOn(t, ctx, f.licenseID); used != 2 || !holders[f.staying] {
		t.Errorf("license: used = %d, holders = %v; want the seat kept", used, holders)
	}
	graph.unassignErr = nil
	if err := svc.UnassignSeat(ctx, f.licenseID, f.staying); err != nil {
		t.Fatalf("retried UnassignSeat() error = %v", err)
	}
}
