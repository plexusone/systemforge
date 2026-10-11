package invite_test

import (
	"context"
	"os"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/internal/pgtest"
)

// TestInviteResourceTargetMigration runs migrations/0009 on PostgreSQL
// against an invites table that lacks the columns, as an earlier version
// left it, and checks an invite can then carry a target and the script is
// repeatable.
func TestInviteResourceTargetMigration(t *testing.T) {
	ctx := context.Background()
	sqlDB := pgtest.Open(t)
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sqlDB)))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, col := range []string{"resource_type", "resource_id", "resource_role"} {
		if _, err := sqlDB.ExecContext(ctx, "ALTER TABLE sf_invites DROP COLUMN "+col); err != nil {
			t.Fatalf("drop %s: %v", col, err)
		}
	}
	script, err := os.ReadFile("../../migrations/0009_invite_resource_target.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	for range 2 { // idempotent
		if _, err := sqlDB.ExecContext(ctx, string(script)); err != nil {
			t.Fatalf("run migration: %v", err)
		}
	}
	orgID, inviter := seedInviteOrg(t, db)
	inv, err := db.Invite.Create().
		SetOrganizationID(orgID).SetInviterPrincipalID(inviter).SetEmail("m@example.com").
		SetToken(uuid.NewString()).SetRole("collaborator").SetExpiresAt(time.Now().Add(time.Hour)).
		SetResourceType("share_project").SetResourceID("p1").SetResourceRole("viewer").
		Save(ctx)
	if err != nil {
		t.Fatalf("create invite with a target: %v", err)
	}
	if inv.ResourceType == nil || *inv.ResourceID != "p1" {
		t.Errorf("stored invite = %+v", inv)
	}
}
