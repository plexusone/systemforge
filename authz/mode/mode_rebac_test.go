//go:build integration

package mode_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/mode"
	"github.com/plexusone/systemforge/authz/rebac/spicedb"
)

// TestNewReBAC builds mode rebac with an embedded SpiceDB, checks that the
// schema was composed from the registered vocabulary, and runs the same
// collaborator lifecycle as the role-based mode.
func TestNewReBAC(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	res, err := mode.New(ctx, authz.ModeConfig{Mode: authz.ModeReBAC}, mode.Deps{
		DB: db, Registry: newRegistry(t), SyncMode: authz.SyncModeStrict,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := res.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if res.Mode != authz.ModeReBAC {
		t.Errorf("mode = %q", res.Mode)
	}
	provider, ok := res.Provider.(*spicedb.Provider)
	if !ok {
		t.Fatalf("provider is %T, want *spicedb.Provider", res.Provider)
	}
	schema, err := provider.Client().ReadSchema(ctx)
	if err != nil {
		t.Fatalf("ReadSchema: %v", err)
	}
	for _, want := range []string{"definition organization", "relation collaborator", "definition modedemo_project"} {
		if !strings.Contains(schema, want) {
			t.Errorf("schema lacks %q", want)
		}
	}
	if _, ok := res.Syncer.(authz.ResourceGrantSyncer); !ok {
		t.Errorf("syncer %T does not write resource grants", res.Syncer)
	}
	exerciseContract(t, db, res, func(org uuid.UUID, id string) {
		if err := provider.AddRelationship(ctx, spicedb.TypeOrganization, org.String(), "org", "modedemo_project", id); err != nil {
			t.Fatalf("link resource: %v", err)
		}
	})
}
