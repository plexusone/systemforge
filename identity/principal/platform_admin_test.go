package principal_test

import (
	"context"
	"errors"
	"testing"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/principal"
)

// Revoking platform administration removes it from the authorization
// backend before it commits: when the backend refuses, the flag stays set,
// whatever the sync mode, and the retried call succeeds.
func TestPlatformAdminRevocationAbortsWhenTheGraphFails(t *testing.T) {
	for _, mode := range []authz.SyncMode{authz.SyncModeStrict, authz.SyncModeEventual} {
		t.Run(string(mode), func(t *testing.T) {
			ctx := context.Background()
			svc, _, syncer := newService(t, principal.WithSyncMode(mode))
			h, err := svc.CreateHuman(ctx, principal.CreateHumanInput{Email: "kim@example.com", DisplayName: "Kim", IsPlatformAdmin: true})
			if err != nil {
				t.Fatalf("CreateHuman: %v", err)
			}
			isAdmin := func() bool {
				t.Helper()
				got, err := svc.GetByID(ctx, h.ID)
				if err != nil || got.Human == nil {
					t.Fatalf("GetByID = %+v, %v", got, err)
				}
				return got.Human.IsPlatformAdmin
			}
			boom := errors.New("graph down")
			no := false

			syncer.mu.Lock()
			syncer.fail = boom
			syncer.mu.Unlock()
			if _, err := svc.UpdateHuman(ctx, h.ID, principal.UpdateHumanInput{IsPlatformAdmin: &no}); !errors.Is(err, boom) {
				t.Errorf("revoke = %v, want the graph error", err)
			}
			if !isAdmin() {
				t.Error("refused revoke was saved")
			}

			syncer.mu.Lock()
			syncer.fail = nil
			syncer.mu.Unlock()
			if _, err := svc.UpdateHuman(ctx, h.ID, principal.UpdateHumanInput{IsPlatformAdmin: &no}); err != nil {
				t.Fatalf("retried revoke: %v", err)
			}
			if isAdmin() {
				t.Error("retried revoke not saved")
			}
			if syncer.admins[h.ID] {
				t.Error("retried revoke not synced")
			}
		})
	}
}
