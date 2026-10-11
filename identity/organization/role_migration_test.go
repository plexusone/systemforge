package organization_test

import (
	"context"
	"os"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/accesschange"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/internal/pgtest"
)

// TestDropEditorViewerRolesMigration runs migrations/0008 on PostgreSQL
// against memberships and invitations stored with the retired roles: editor
// maps to member, viewer to collaborator, current rows are untouched, an
// access change is recorded for each active membership that changed, and a
// second run changes nothing.
func TestDropEditorViewerRolesMigration(t *testing.T) {
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

	owner, err := db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("Owner").Save(ctx)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	org, err := organization.NewService(db).Create(ctx, organization.CreateOrganizationInput{
		Name: "Acme", Slug: "acme-" + uuid.NewString()[:8], OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner.ID,
	})
	if err != nil {
		t.Fatalf("organization: %v", err)
	}
	add := func(role string, active bool) uuid.UUID {
		t.Helper()
		p, err := db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName(role).Save(ctx)
		if err != nil {
			t.Fatalf("principal: %v", err)
		}
		if _, err := db.PrincipalMembership.Create().SetPrincipalID(p.ID).SetOrganizationID(org.ID).SetRole(role).SetActive(active).Save(ctx); err != nil {
			t.Fatalf("membership: %v", err)
		}
		return p.ID
	}
	editor, viewer, member, admin := add("editor", true), add("viewer", true), add("member", true), add("admin", true)
	inactiveEditor := add("editor", false)
	for _, role := range []string{"editor", "viewer", "member"} {
		if _, err := db.Invite.Create().
			SetOrganizationID(org.ID).SetInviterPrincipalID(owner.ID).SetEmail(role + "@example.com").
			SetToken(uuid.NewString()).SetRole(role).SetExpiresAt(time.Now().Add(24 * time.Hour)).Save(ctx); err != nil {
			t.Fatalf("invite %s: %v", role, err)
		}
	}

	script, err := os.ReadFile("../../migrations/0008_drop_editor_viewer_roles.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	roleOf := func(id uuid.UUID) string {
		t.Helper()
		m, err := db.PrincipalMembership.Query().Where(principalmembership.PrincipalID(id), principalmembership.OrganizationID(org.ID)).Only(ctx)
		if err != nil {
			t.Fatalf("membership: %v", err)
		}
		return m.Role
	}
	for run := range 2 { // idempotent
		if _, err := sqlDB.ExecContext(ctx, string(script)); err != nil {
			t.Fatalf("run %d: %v", run+1, err)
		}
		for who, want := range map[string]string{
			"editor": "member", "viewer": "collaborator", "member": "member", "admin": "admin", "inactive editor": "member",
		} {
			id := map[string]uuid.UUID{"editor": editor, "viewer": viewer, "member": member, "admin": admin, "inactive editor": inactiveEditor}[who]
			if got := roleOf(id); got != want {
				t.Errorf("run %d: %s is now %q, want %q", run+1, who, got, want)
			}
		}
		if got := roleOf(owner.ID); got != "owner" {
			t.Errorf("run %d: owner is now %q", run+1, got)
		}
		n, err := db.AccessChange.Query().Where(accesschange.OrganizationID(org.ID), accesschange.Reason("org_role_changed")).Count(ctx)
		if err != nil {
			t.Fatalf("count access changes: %v", err)
		}
		if n != 2 {
			t.Errorf("run %d: %d access changes recorded, want 2 (the active editor and viewer, once)", run+1, n)
		}
		roles := map[string]int{}
		invites, err := db.Invite.Query().All(ctx)
		if err != nil {
			t.Fatalf("invites: %v", err)
		}
		for _, inv := range invites {
			roles[inv.Role]++
		}
		if roles["editor"] != 0 || roles["viewer"] != 0 || roles["member"] != 2 || roles["collaborator"] != 1 {
			t.Errorf("run %d: invite roles = %v, want member 2 and collaborator 1", run+1, roles)
		}
	}
}
