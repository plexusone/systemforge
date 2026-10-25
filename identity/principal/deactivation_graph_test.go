package principal_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/internal/pgtest"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// graphWorld is a platform administrator who belongs to an organization
// with an application role and a resource grant, and manages a child.
type graphWorld struct {
	db         *ent.Client
	svc        principal.Service
	rec        *syncrec.Recorder
	id, org    uuid.UUID
	child      uuid.UUID
	grantCalls []string // the calls that write its access
	revokes    []string // the calls that remove it
}

func newGraphWorld(t *testing.T, db *ent.Client) *graphWorld {
	t.Helper()
	ctx := context.Background()
	rec := syncrec.New()
	w := &graphWorld{db: db, rec: rec, svc: principal.NewService(db, principal.WithAuthzSyncer(rec), principal.WithSyncMode(authz.SyncModeStrict))}
	h, err := w.svc.CreateHuman(ctx, principal.CreateHumanInput{Email: uuid.NewString() + "@example.com", DisplayName: "Kim", IsPlatformAdmin: true})
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	w.id = h.ID
	child, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(uuid.NewString()).SetDisplayName("Child").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.child = child.ID
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
	if _, err := db.ResourceGrant.Create().SetOrganizationID(w.org).SetPrincipalID(w.id).SetResourceType("notes_board").SetResourceID("b1").SetRole("viewer").Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ManagerRelationship.Create().SetManagedPrincipalID(w.child).SetManagerPrincipalID(w.id).SetRole("guardian").Save(ctx); err != nil {
		t.Fatal(err)
	}
	w.grantCalls = []string{
		fmt.Sprintf("AddOrgMembership:%s:%s:member", w.id, w.org),
		fmt.Sprintf("AddAppRole:%s:%s:notes:editor", w.id, w.org),
		fmt.Sprintf("SetResourceGrant:%s:%s:notes_board:b1:viewer", w.id, w.org),
		fmt.Sprintf("SetPlatformAdmin:%s:true", w.id),
		fmt.Sprintf("AddPrincipalManager:%s:%s:guardian", w.child, w.id),
	}
	w.revokes = []string{
		fmt.Sprintf("RemoveOrgMembership:%s:%s:member", w.id, w.org),
		fmt.Sprintf("RemoveAppRole:%s:%s:notes:editor", w.id, w.org),
		fmt.Sprintf("RemoveResourceGrant:%s:%s:notes_board:b1", w.id, w.org),
		fmt.Sprintf("SetPlatformAdmin:%s:false", w.id),
		fmt.Sprintf("RemovePrincipalManager:%s:%s:guardian", w.child, w.id),
	}
	rec.Reset()
	return w
}

func (w *graphWorld) active(t *testing.T) bool {
	t.Helper()
	p, err := w.db.Principal.Get(context.Background(), w.id)
	if err != nil {
		t.Fatal(err)
	}
	return p.Active
}

func requireCalls(t *testing.T, what string, got, want []string) {
	t.Helper()
	for _, c := range want {
		if !slices.Contains(got, c) {
			t.Errorf("%s: missing %s; calls %v", what, c, got)
		}
	}
}

// Deactivation removes every relationship the principal holds before it
// commits, and reactivation writes them back.
func TestDeactivationRemovesGraphAccess(t *testing.T) {
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	testDeactivationGraph(t, db)
}

func TestDeactivationRemovesGraphAccessPostgres(t *testing.T) {
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, pgtest.Open(t))))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	testDeactivationGraph(t, db)
}

func testDeactivationGraph(t *testing.T, db *ent.Client) {
	t.Helper()
	ctx := context.Background()
	w := newGraphWorld(t, db)

	// The graph refuses: the principal stays active.
	boom := errors.New("graph down")
	w.rec.RemoveErr = boom
	if err := w.svc.Deactivate(ctx, w.id); !errors.Is(err, boom) {
		t.Fatalf("refused Deactivate = %v, want the graph error", err)
	}
	if !w.active(t) {
		t.Error("refused deactivation was saved")
	}
	w.rec.RemoveErr = nil
	w.rec.Reset()

	if err := w.svc.Deactivate(ctx, w.id); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if w.active(t) {
		t.Error("deactivation not saved")
	}
	requireCalls(t, "deactivation", w.rec.Calls(), w.revokes)

	w.rec.Reset()
	if err := w.svc.Reactivate(ctx, w.id); err != nil {
		t.Fatalf("Reactivate: %v", err)
	}
	requireCalls(t, "reactivation", w.rec.Calls(), w.grantCalls)

	// Update with Active does the same.
	w.rec.Reset()
	no, yes := false, true
	if _, err := w.svc.Update(ctx, w.id, principal.UpdateInput{Active: &no}); err != nil {
		t.Fatalf("Update(inactive): %v", err)
	}
	requireCalls(t, "Update(inactive)", w.rec.Calls(), w.revokes)

	// Access revoked while the principal was inactive is not restored.
	if _, err := db.PrincipalMembership.Delete().Where(principalmembership.PrincipalID(w.id)).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	w.rec.Reset()
	if _, err := w.svc.Update(ctx, w.id, principal.UpdateInput{Active: &yes}); err != nil {
		t.Fatalf("Update(active): %v", err)
	}
	calls := w.rec.Calls()
	for _, c := range w.grantCalls[:3] {
		if slices.Contains(calls, c) {
			t.Errorf("reactivation wrote %s for a removed membership", c)
		}
	}
	requireCalls(t, "reactivation without membership", calls, w.grantCalls[3:])
}
