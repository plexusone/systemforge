package managedprincipal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// Removing a manager, releasing and deleting remove the relations from the
// graph before they commit: when the graph refuses, nothing changes,
// whatever the sync mode, and the retried call succeeds.
func TestManagerRevocationsAbortWhenTheGraphFails(t *testing.T) {
	for _, mode := range []authz.SyncMode{authz.SyncModeStrict, authz.SyncModeEventual} {
		t.Run(string(mode), func(t *testing.T) {
			ctx := context.Background()
			db := openSQLite(t)
			rec := syncrec.New()
			svc := NewService(db, gate{client: true}, WithAuthzSyncer(rec, mode), WithDirectManagerAdds())
			boom := errors.New("graph down")
			parent := addHuman(t, db, "parent@example.com", true)
			teacher := addHuman(t, db, "teacher@example.com", true)
			learner := func(email string) uuid.UUID {
				t.Helper()
				id, err := svc.Create(ctx, CreateInput{ActorID: parent, DisplayName: "Learner", ClientID: client, Email: email,
					Managers: []ManagerInput{{parent, RoleGuardian}, {teacher, RoleEducator}}})
				if err != nil {
					t.Fatalf("Create: %v", err)
				}
				if err := svc.VerifyEmail(ctx, id, time.Now()); err != nil {
					t.Fatalf("VerifyEmail: %v", err)
				}
				return id
			}
			roles := func(manager, managed uuid.UUID) []string {
				t.Helper()
				r, err := svc.ManagerRoles(ctx, manager, managed)
				if err != nil {
					t.Fatalf("ManagerRoles: %v", err)
				}
				return r
			}
			a, b := learner("a@example.com"), learner("b@example.com")

			rec.RemoveErr = boom
			if err := svc.RemoveManager(ctx, a, ManagerInput{teacher, RoleEducator}, parent); !errors.Is(err, boom) {
				t.Errorf("RemoveManager = %v, want the graph error", err)
			}
			if r := roles(teacher, a); !slices.Equal(r, []string{RoleEducator}) {
				t.Errorf("educator after refused removal = %v", r)
			}
			if err := svc.Release(ctx, parent, a); !errors.Is(err, boom) {
				t.Errorf("Release = %v, want the graph error", err)
			}
			if r := roles(parent, a); !slices.Equal(r, []string{RoleGuardian}) {
				t.Errorf("guardian after refused release = %v", r)
			}
			if err := svc.Delete(ctx, parent, b); !errors.Is(err, boom) {
				t.Errorf("Delete = %v, want the graph error", err)
			}
			if active, err := db.Principal.Query().Where(entprincipal.ID(b), entprincipal.Active(true)).Exist(ctx); err != nil || !active {
				t.Errorf("principal after refused delete: active %v, %v", active, err)
			}

			rec.RemoveErr = nil
			rec.Reset()
			if err := svc.RemoveManager(ctx, a, ManagerInput{teacher, RoleEducator}, parent); err != nil {
				t.Fatalf("retried RemoveManager: %v", err)
			}
			if err := svc.Release(ctx, parent, a); err != nil {
				t.Fatalf("retried Release: %v", err)
			}
			if err := svc.Delete(ctx, parent, b); err != nil {
				t.Fatalf("retried Delete: %v", err)
			}
			if r := roles(parent, a); len(r) != 0 {
				t.Errorf("guardian after release = %v", r)
			}
			calls := rec.Calls()
			for _, want := range []string{
				fmt.Sprintf("RemovePrincipalManager:%s:%s:educator", a, teacher),
				fmt.Sprintf("RemovePrincipalManager:%s:%s:guardian", a, parent),
				fmt.Sprintf("RemovePrincipalManager:%s:%s:guardian", b, parent),
				fmt.Sprintf("UnregisterPrincipal:%s", b),
			} {
				if !slices.Contains(calls, want) {
					t.Errorf("retries did not sync %s; calls %v", want, calls)
				}
			}
		})
	}
}
