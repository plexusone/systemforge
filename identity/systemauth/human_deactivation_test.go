package systemauth_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	entaccesschange "github.com/plexusone/systemforge/identity/ent/accesschange"
	"github.com/plexusone/systemforge/identity/graphlock"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// deactivationWorld is a human who belongs to an organization with an
// application role, kept in EntStorage with a recording syncer.
type deactivationWorld struct {
	db      *ent.Client
	st      *systemauth.EntStorage
	rec     *syncrec.Recorder
	id, org uuid.UUID
	revokes []string // the calls that remove its access
	grants  []string // the calls that write it back
}

func newDeactivationWorld(t *testing.T, db *ent.Client) *deactivationWorld {
	t.Helper()
	ctx := context.Background()
	rec := syncrec.New()
	w := &deactivationWorld{db: db, rec: rec, st: systemauth.NewEntStorage(db, systemauth.WithEntAuthzSyncer(rec, authz.SyncModeStrict))}
	h := &systemauth.HumanPrincipal{Email: uuid.NewString() + "@example.com", DisplayName: "Kim", Active: true}
	if err := w.st.CreateHuman(ctx, h); err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	w.id = h.ID
	o, err := db.Organization.Create().SetName("Acme").SetSlug("acme-" + uuid.NewString()[:8]).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.org = o.ID
	if _, err := db.PrincipalMembership.Create().SetOrganizationID(w.org).SetPrincipalID(w.id).SetRole("member").SetActive(true).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AppRole.Create().SetOrganizationID(w.org).SetPrincipalID(w.id).SetApplication("notes").SetRole("editor").Save(ctx); err != nil {
		t.Fatal(err)
	}
	w.revokes = []string{
		fmt.Sprintf("RemoveOrgMembership:%s:%s:member", w.id, w.org),
		fmt.Sprintf("RemoveAppRole:%s:%s:notes:editor", w.id, w.org),
	}
	w.grants = []string{
		fmt.Sprintf("AddOrgMembership:%s:%s:member", w.id, w.org),
		fmt.Sprintf("AddAppRole:%s:%s:notes:editor", w.id, w.org),
	}
	rec.Reset()
	return w
}

func (w *deactivationWorld) human(t *testing.T) *systemauth.HumanPrincipal {
	t.Helper()
	h, err := w.st.GetHuman(context.Background(), w.id)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (w *deactivationWorld) deactivations(t *testing.T) int {
	t.Helper()
	n, err := w.db.AccessChange.Query().
		Where(entaccesschange.PrincipalIDEQ(w.id), entaccesschange.ReasonEQ(string(accesschange.Deactivated))).
		Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func requireRecorded(t *testing.T, what string, got, want []string) {
	t.Helper()
	for _, c := range want {
		if !slices.Contains(got, c) {
			t.Errorf("%s: missing %s; calls %v", what, c, got)
		}
	}
}

// UpdateHuman deactivates through the principal service: the principal's
// access leaves the graph before the deactivation commits, a refusal
// leaves it active, and reactivation writes the access back.
func TestUpdateHumanDeactivationRemovesGraphAccess(t *testing.T) {
	for _, b := range entBackends {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			w := newDeactivationWorld(t, b.open(t))

			// The graph refuses: the profile change is saved, the
			// principal stays active, and the error is returned.
			boom := errors.New("graph down")
			w.rec.RemoveErr = boom
			h := w.human(t)
			h.DisplayName = "Kim Lee"
			h.Active = false
			if err := w.st.UpdateHuman(ctx, h); !errors.Is(err, boom) {
				t.Fatalf("refused UpdateHuman = %v, want the graph error", err)
			}
			if got := w.human(t); !got.Active || got.DisplayName != "Kim Lee" {
				t.Errorf("after a refusal: active %v, name %q; want active, Kim Lee", got.Active, got.DisplayName)
			}
			if n := w.deactivations(t); n != 0 {
				t.Errorf("a refused deactivation recorded %d access changes", n)
			}

			// Retried, it removes the access and records the change.
			w.rec.RemoveErr = nil
			w.rec.Reset()
			if err := w.st.UpdateHuman(ctx, h); err != nil {
				t.Fatalf("UpdateHuman(inactive): %v", err)
			}
			if w.human(t).Active {
				t.Error("deactivation not saved")
			}
			requireRecorded(t, "deactivation", w.rec.Calls(), w.revokes)
			if n := w.deactivations(t); n != 1 {
				t.Errorf("deactivation recorded %d access changes, want 1", n)
			}

			// An update that leaves Active alone touches nothing.
			w.rec.Reset()
			h.DisplayName = "Kim"
			if err := w.st.UpdateHuman(ctx, h); err != nil {
				t.Fatalf("UpdateHuman(profile): %v", err)
			}
			if calls := w.rec.Calls(); len(calls) != 0 {
				t.Errorf("a profile update wrote to the graph: %v", calls)
			}
			if n := w.deactivations(t); n != 1 {
				t.Errorf("a profile update recorded a deactivation (%d)", n)
			}

			// Reactivation writes the access back.
			w.rec.Reset()
			h.Active = true
			if err := w.st.UpdateHuman(ctx, h); err != nil {
				t.Fatalf("UpdateHuman(active): %v", err)
			}
			if !w.human(t).Active {
				t.Error("reactivation not saved")
			}
			requireRecorded(t, "reactivation", w.rec.Calls(), w.grants)
		})
	}
}

// A federation delete deactivates the linked principal through UpdateHuman,
// removing its access from the graph.
func TestFederationDeleteRemovesGraphAccess(t *testing.T) {
	for _, b := range entBackends {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			w := newDeactivationWorld(t, b.open(t))
			sync := systemauth.NewDefaultIdentitySyncHandler(w.st)
			fi := &systemauth.GlobalIdentity{ID: uuid.New(), Email: w.human(t).Email, Status: "active"}
			resp, err := sync.SyncIdentity(ctx, &systemauth.IdentitySyncRequest{Action: "create", Identity: fi})
			if err != nil || resp.Status != "synced" || resp.LocalPrincipalID != w.id {
				t.Fatalf("create: %+v, %v; want principal %s adopted", resp, err, w.id)
			}

			w.rec.Reset()
			resp, err = sync.SyncIdentity(ctx, &systemauth.IdentitySyncRequest{Action: "delete", Identity: fi})
			if err != nil || resp.Status != "synced" {
				t.Fatalf("delete: %+v, %v", resp, err)
			}
			if w.human(t).Active {
				t.Error("federation delete left the principal active")
			}
			requireRecorded(t, "federation delete", w.rec.Calls(), w.revokes)
		})
	}
}

// On PostgreSQL the deactivation holds the principal's graph lock, so it
// waits for a transaction holding it, such as a reconciler repair, and
// commits only after that one ends.
func TestUpdateHumanDeactivationTakesTheGraphLock(t *testing.T) {
	ctx := context.Background()
	w := newDeactivationWorld(t, openPostgres(t))

	holder, err := w.db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := graphlock.Lock(ctx, holder, graphlock.Principal(w.id)); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	h := w.human(t)
	h.Active = false
	done := make(chan error, 1)
	go func() { done <- w.st.UpdateHuman(ctx, h) }()
	select {
	case err := <-done:
		t.Fatalf("UpdateHuman returned while another transaction held the principal's lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if !w.human(t).Active {
		t.Error("the deactivation committed while waiting for the lock")
	}
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("UpdateHuman: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("UpdateHuman still waiting after the lock was released")
	}
	if w.human(t).Active {
		t.Error("deactivation not saved")
	}
	requireRecorded(t, "deactivation", w.rec.Calls(), w.revokes)
}
