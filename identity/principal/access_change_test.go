package principal_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

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

// TestApplicationAccessTokenTTLBounds verifies the ADR-010 default of ten
// minutes for an application's access tokens and the fifteen minute cap.
func TestApplicationAccessTokenTTLBounds(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newService(t)
	for ttl, want := range map[int]int{0: 600, 300: 300, 900: 900, 86400: 900} {
		app, err := svc.CreateApplication(ctx, principal.CreateApplicationInput{
			ClientID: uuid.NewString(), DisplayName: "App", AppType: principal.AppTypeSPA,
			RedirectURIs: []string{"https://app.example.com/cb"}, Public: true, AccessTokenTTLSeconds: ttl,
		})
		if err != nil {
			t.Fatalf("CreateApplication ttl %d: %v", ttl, err)
		}
		if app.Application.AccessTokenTTLSeconds != want {
			t.Errorf("ttl %d stored as %d, want %d", ttl, app.Application.AccessTokenTTLSeconds, want)
		}
	}
}
