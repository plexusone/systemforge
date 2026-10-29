package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

func TestOrgMemberCommands(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "sa.db") + "?_fk=1"
	db := []string{"--db-driver", "sqlite", "--db-dsn", dsn, "--issuer", "https://auth.example.com"}
	cli := func(args ...string) (string, error) { return runCLI(t, append(args, db...)...) }
	if out, err := cli("migrate"); err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}

	conn, err := systemauthsvc.OpenDatabase(&systemauth.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	var ids []uuid.UUID
	for _, email := range []string{"owner@example.com", "ada@example.com"} {
		p, err := conn.Client.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(email).SetDisplayName(email).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Client.Human.Create().SetPrincipalID(p.ID).SetEmail(email).Save(ctx); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, p.ID)
	}
	owner := ids[0]
	if _, err := organization.NewService(conn.Client).Create(ctx, organization.CreateOrganizationInput{
		Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner,
	}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	if out, err := cli("org", "member", "add", "acme", "ada@example.com", "--org-role", "admin"); err != nil || !strings.Contains(out, "added ada@example.com to acme as admin") {
		t.Fatalf("add: %v\n%s", err, out)
	}
	out, err := cli("org", "member", "list", "acme")
	if err != nil || !strings.Contains(out, "ada@example.com") || !strings.Contains(out, ids[1].String()) {
		t.Fatalf("list: %v\n%s", err, out)
	}
	// The standalone server knows no application, so it grants no roles.
	if _, err := cli("org", "member", "add", "acme", "ada@example.com", "--role", "billing:admin"); err == nil {
		t.Error("application role granted without a vocabulary")
	}
	if out, err := cli("org", "member", "remove", "acme", "ada@example.com"); err != nil || !strings.Contains(out, "removed ada@example.com from acme") {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	out, _ = cli("org", "member", "list", "acme")
	if strings.Contains(out, "ada@example.com") {
		t.Errorf("list after remove:\n%s", out)
	}
}
