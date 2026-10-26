//go:build integration

package mode_test

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/mode"
	"github.com/plexusone/systemforge/authz/rebac/spicedb"
)

// TestReconcileEmbeddedSpiceDB repairs drift in both directions in an
// embedded SpiceDB built by mode.New, reading the graph in pages smaller
// than its contents.
func TestReconcileEmbeddedSpiceDB(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	res, err := mode.New(ctx, authz.ModeConfig{
		Mode:      authz.ModeReBAC,
		Reconcile: &authz.ReconcileConfig{PageSize: 2, Interval: "0"},
	}, mode.Deps{DB: db, Registry: recRegistry(t), SyncMode: authz.SyncModeStrict})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := res.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if res.Reconciler == nil {
		t.Fatal("mode rebac has no reconciler")
	}
	if !res.Schedule.OnStartup || res.Schedule.Interval != 0 {
		t.Errorf("schedule = %+v, want startup only", res.Schedule)
	}
	client := res.Provider.(*spicedb.Provider).Client()

	w := newWorld(t, db)
	var seed []*spicedb.Relationship
	for i, r := range w.desired {
		if i%2 == 0 {
			seed = append(seed, &r)
		}
	}
	for _, r := range append(w.stale(), w.foreign()...) {
		seed = append(seed, &r)
	}
	if err := client.WriteRelationships(ctx, seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The startup run of the configured schedule.
	if err := res.RunReconciler(ctx); err != nil {
		t.Fatalf("RunReconciler: %v", err)
	}
	stats := res.Reconciler.Stats()
	if stats.Runs != 1 || stats.LastError != nil {
		t.Fatalf("stats = %+v", stats)
	}
	if got := stats.Last; got.Added != len(w.desired)/2 || got.Removed != len(w.stale()) {
		t.Errorf("result = %+v", got)
	}

	var got []spicedb.Relationship
	for _, typ := range []string{"organization", "platform", "principal", "recdemo_org", "recdemo_doc"} {
		if err := client.ReadRelationships(ctx, &spicedb.RelationshipFilter{ResourceType: typ}, 3, func(r *spicedb.Relationship) error {
			got = append(got, *r)
			return nil
		}); err != nil {
			t.Fatalf("read %s: %v", typ, err)
		}
	}
	want := append(slices.Clone(w.desired), w.foreign()...)
	sortByString := func(a, b spicedb.Relationship) int { return cmp.Compare(fmt.Sprint(a), fmt.Sprint(b)) }
	slices.SortFunc(want, sortByString)
	slices.SortFunc(got, sortByString)
	if !slices.Equal(got, want) {
		t.Errorf("graph after reconcile:\n got %v\nwant %v", got, want)
	}

	// The repaired graph answers checks as the tables say.
	for _, c := range []struct {
		who  string
		perm string
		want bool
	}{
		{w.member.String(), spicedb.PermView, true},
		{w.paused.String(), spicedb.PermView, false},
	} {
		ok, err := client.Check(ctx, &spicedb.CheckRequest{ResourceType: "organization", ResourceID: w.org.String(), Permission: c.perm, SubjectType: "principal", SubjectID: c.who})
		if err != nil || ok != c.want {
			t.Errorf("check %s %s = %v, %v; want %v", c.who, c.perm, ok, err, c.want)
		}
	}

	// Deleting a relationship that is absent succeeds, so a revocation
	// can be retried after the graph already removed it.
	gone := w.stale()[0]
	if err := client.DeleteRelationship(ctx, &gone); err != nil {
		t.Errorf("deleting an absent relationship: %v", err)
	}
}
