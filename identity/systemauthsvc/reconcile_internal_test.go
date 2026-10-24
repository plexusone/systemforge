package systemauthsvc

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/authz/mode"
	"github.com/plexusone/systemforge/authz/rebac/spicedb"
	"github.com/plexusone/systemforge/identity/ent/enttest"
)

// emptyGraph is a graph with no relationships that accepts writes.
type emptyGraph struct{}

func (emptyGraph) ReadRelationships(context.Context, *spicedb.RelationshipFilter, int, func(*spicedb.Relationship) error) error {
	return nil
}
func (emptyGraph) WriteRelationships(context.Context, []*spicedb.Relationship) error { return nil }
func (emptyGraph) DeleteRelationshipsExact(context.Context, []*spicedb.Relationship) error {
	return nil
}

// RunJobs runs the graph reconciler of a rebac authorization mode on its
// schedule, and AuthzReconciler exposes it for on-demand runs.
func TestRunJobsRunsTheReconciler(t *testing.T) {
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	rc := mode.NewReconciler(db, emptyGraph{}, mode.WithReconcileLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	s := &Service{authz: &mode.Result{Reconciler: rc, Schedule: mode.ReconcileSchedule{OnStartup: true}}}
	if s.AuthzReconciler() != rc {
		t.Fatal("AuthzReconciler does not return the mode's reconciler")
	}
	if err := s.RunJobs(t.Context()); err != nil {
		t.Fatalf("RunJobs: %v", err)
	}
	if st := rc.Stats(); st.Runs != 1 || st.LastError != nil {
		t.Errorf("reconciler stats = %+v, want one successful startup run", st)
	}
	if (&Service{}).AuthzReconciler() != nil {
		t.Error("a service without an authorization mode has a reconciler")
	}
}
