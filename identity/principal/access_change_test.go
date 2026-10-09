package principal_test

import (
	"context"
	"testing"
	"time"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/principal"
)

// TestDeactivateRecordsAccessChange verifies that deactivating a principal
// records an access change for it, in every organization, and announces it
// (ADR-010).
func TestDeactivateRecordsAccessChange(t *testing.T) {
	ctx := context.Background()
	var announced []accesschange.Change
	svc, db, _ := newService(t, principal.WithAccessChangeSink(accesschange.SinkFunc(func(c accesschange.Change) {
		announced = append(announced, c)
	})))
	h, err := svc.CreateHuman(ctx, principal.CreateHumanInput{Email: "kim@example.com", DisplayName: "Kim"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Reactivate(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	if len(announced) != 0 {
		t.Fatalf("reactivation announced %+v", announced)
	}
	if err := svc.Deactivate(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	if len(announced) != 1 || announced[0].PrincipalID != h.ID || announced[0].OrganizationID != nil || announced[0].Reason != accesschange.Deactivated {
		t.Fatalf("announced = %+v", announced)
	}
	stored, err := accesschange.Since(ctx, db, time.Time{}, 0)
	if err != nil || len(stored) != 1 || stored[0].PrincipalID != h.ID {
		t.Errorf("stored = %+v, %v", stored, err)
	}
}
