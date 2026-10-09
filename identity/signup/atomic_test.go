package signup

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/invite"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/internal/syncrec"
)

func newSyncedFixture(t *testing.T, rec *syncrec.Recorder, mode authz.SyncMode) (*ent.Client, Service) {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	principals := principal.NewService(db, principal.WithAuthzSyncer(rec), principal.WithSyncMode(mode))
	orgs := organization.NewService(db, organization.WithAuthzSyncer(rec), organization.WithSyncMode(mode))
	return db, NewService(db, principals, orgs, invite.NewService(db, "https://app.example.com"))
}

// TestSignupRegistersWithSyncerAfterCommit verifies that a signup registers
// the principal and then the organization with its owner.
func TestSignupRegistersWithSyncerAfterCommit(t *testing.T) {
	rec := syncrec.New()
	_, svc := newSyncedFixture(t, rec, authz.SyncModeEventual)
	res, err := svc.Signup(context.Background(), input("kim@example.com", "kim"))
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	want := []string{
		"RegisterPrincipal:" + res.Principal.ID.String(),
		"RegisterOrganization:" + res.PersonalOrganization.ID.String() + ":" + res.Principal.ID.String(),
	}
	got := rec.Calls()
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("syncer calls = %v, want %v", got, want)
	}
	if res.Membership == nil || res.Membership.Role != organization.RoleOwner || res.Membership.PrincipalID != res.Principal.ID {
		t.Errorf("membership = %+v", res.Membership)
	}
}

// TestSignupIsOneTransaction verifies that a failure after the principal
// write rolls it back instead of deleting it afterwards: deleting
// principals is made to fail, so only a rollback can leave none behind.
func TestSignupIsOneTransaction(t *testing.T) {
	ctx := context.Background()
	rec := syncrec.New()
	db, svc := newSyncedFixture(t, rec, authz.SyncModeEventual)
	boom := errors.New("organization store unavailable")
	db.Organization.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if m.Op().Is(ent.OpCreate) {
				return nil, boom
			}
			return next.Mutate(ctx, m)
		})
	})
	db.Principal.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if m.Op().Is(ent.OpDelete | ent.OpDeleteOne) {
				return nil, errors.New("principal deletes are not allowed")
			}
			return next.Mutate(ctx, m)
		})
	})

	_, err := svc.Signup(ctx, input("kim@example.com", "kim"))
	if !errors.Is(err, boom) {
		t.Fatalf("Signup = %v, want the organization failure", err)
	}
	if n := db.Principal.Query().CountX(ctx); n != 0 {
		t.Errorf("principals after a failed signup = %d, want 0", n)
	}
	if n := db.Human.Query().CountX(ctx); n != 0 {
		t.Errorf("humans after a failed signup = %d, want 0", n)
	}
	if got := rec.Calls(); len(got) != 0 {
		t.Errorf("a rolled-back signup was synced: %v", got)
	}
}

// TestSignupStrictSyncFailure verifies that in strict mode a failed
// registration is reported while the committed signup stays.
func TestSignupStrictSyncFailure(t *testing.T) {
	ctx := context.Background()
	rec := syncrec.New()
	rec.Err = errors.New("authz down")
	db, svc := newSyncedFixture(t, rec, authz.SyncModeStrict)
	if _, err := svc.Signup(ctx, input("kim@example.com", "kim")); err == nil {
		t.Fatal("expected the sync failure")
	}
	if n := db.Organization.Query().CountX(ctx); n != 1 {
		t.Errorf("organizations = %d, want the committed signup", n)
	}
}
