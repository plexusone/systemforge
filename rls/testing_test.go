package rls_test

import (
	"context"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/internal/pgtest"
	"github.com/plexusone/systemforge/rls"
)

// TestSetupHelpersAgainstSchema runs the tenant and user setup helpers
// against the real identity schema, so their raw SQL stays in step with it.
// It needs PostgreSQL and is skipped unless pgtest.EnvDSN is set.
func TestSetupHelpersAgainstSchema(t *testing.T) {
	db := pgtest.Open(t)
	ctx := context.Background()
	// The Ent client is not closed: closing it would close db, which pgtest owns.
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	if err := client.Schema.Create(ctx); err != nil {
		t.Fatalf("creating schema: %v", err)
	}

	th := rls.NewTestHelper(t, db, nil)
	tenantID, cleanupTenant := th.SetupTestTenant("acme")
	userID, cleanupUser := th.SetupTestUser(tenantID, "ada@example.com", "admin")

	m, err := client.PrincipalMembership.Query().WithPrincipal().Only(ctx)
	if err != nil {
		t.Fatalf("membership: %v", err)
	}
	if m.OrganizationID != tenantID || m.PrincipalID != userID || m.Role != "admin" || !m.Active {
		t.Errorf("membership = %+v", m)
	}
	h, err := client.Human.Query().Only(ctx)
	if err != nil || h.PrincipalID != userID || h.Email != "ada@example.com" {
		t.Errorf("human = %+v, %v", h, err)
	}

	cleanupUser()
	cleanupTenant()
	for name, count := range map[string]func(context.Context) (int, error){
		"principals":  client.Principal.Query().Count,
		"humans":      client.Human.Query().Count,
		"memberships": client.PrincipalMembership.Query().Count,
		"orgs":        client.Organization.Query().Count,
	} {
		if n, err := count(ctx); err != nil || n != 0 {
			t.Errorf("%s after cleanup = %d, %v; want 0", name, n, err)
		}
	}
}

// TestMigrateSystemForgeTables enables RLS on every table in
// SystemForgeTables against the real identity schema, so the list cannot
// name a table the schema no longer has. It needs PostgreSQL and is skipped
// unless pgtest.EnvDSN is set.
func TestMigrateSystemForgeTables(t *testing.T) {
	db := pgtest.Open(t)
	ctx := context.Background()
	// The Ent client is not closed: closing it would close db, which pgtest owns.
	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
	if err := client.Schema.Create(ctx); err != nil {
		t.Fatalf("creating schema: %v", err)
	}

	m := rls.NewMigrator(db, nil)
	if err := m.MigrateSystemForge(ctx); err != nil {
		t.Fatalf("MigrateSystemForge: %v", err)
	}
	statuses, err := m.VerifyRLS(ctx)
	if err != nil {
		t.Fatalf("VerifyRLS: %v", err)
	}
	if len(statuses) != len(rls.SystemForgeTables) {
		t.Fatalf("statuses = %d, want %d", len(statuses), len(rls.SystemForgeTables))
	}
	for _, s := range statuses {
		if !s.RLSEnabled || !s.RLSForced || !s.HasPolicies {
			t.Errorf("%s: %+v, want RLS enabled, forced, and with policies", s.Table, s)
		}
	}
}
