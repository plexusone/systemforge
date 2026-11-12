package billingcmd_test

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"

	"github.com/plexusone/systemforge/billing/billingcmd"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

const planSpec = `{"formatVersion":"1","app":"a","currency":"usd","defaultPlan":"free",
	"applications":[{"id":"a","name":"A"}],
	"tiers":[{"id":"free","name":"Free","rank":1},{"id":"internal","name":"Internal","rank":99}],
	"plans":[{"id":"free","name":"Free","tier":"free","selfServe":true},
		{"id":"internal","name":"Internal","tier":"internal","internal":true}],
	"entitlements":[{"tier":"free","application":"a","seats":1},{"tier":"internal","application":"a","seats":10}]}`

func TestPlanCommands(t *testing.T) {
	ctx := t.Context()
	spec, err := pricingspec.Load(strings.NewReader(planSpec))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &systemauthsvc.Config{
		Billing:  &systemauth.BillingConfig{},
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: "file:" + filepath.Join(t.TempDir(), "sa.db") + "?_fk=1"},
	}
	if err := systemauthsvc.Migrate(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	conn, err := systemauthsvc.OpenDatabase(cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	p, err := conn.Client.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier("owner@example.com").SetDisplayName("Owner").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Client.Human.Create().SetPrincipalID(p.ID).SetEmail("owner@example.com").Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := organization.NewService(conn.Client).Create(ctx, organization.CreateOrganizationInput{
		Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &p.ID,
	}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	run := func(args ...string) (string, error) {
		cmd := billingcmd.Command(func(context.Context) (*systemauthsvc.Config, *pricingspec.Spec, error) {
			return cfg, spec, nil
		})
		var out bytes.Buffer
		cmd.SetArgs(append([]string{"plan"}, args...))
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.ExecuteContext(ctx)
		return out.String(), err
	}

	if out, err := run("show", "acme"); err != nil || !strings.Contains(out, "free") || !strings.Contains(out, "subscription or default") {
		t.Fatalf("show before: %v\n%s", err, out)
	}
	if out, err := run("set", "OWNER@example.com", "internal", "--note", "runs the service"); err != nil ||
		!strings.Contains(out, "internal") || !strings.Contains(out, "operator") || !strings.Contains(out, "runs the service") {
		t.Fatalf("set by the owner's email: %v\n%s", err, out)
	}
	if out, err := run("list"); err != nil || !strings.Contains(out, "acme") || !strings.Contains(out, "internal") {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if _, err := run("set", "acme", "platinum"); err == nil || !strings.Contains(err.Error(), "the plans are free, internal") {
		t.Errorf("an unknown plan: %v", err)
	}
	if _, err := run("set", "nobody@example.com", "internal"); err == nil || !strings.Contains(err.Error(), "signs in once") {
		t.Errorf("an unknown person: %v", err)
	}
	if out, err := run("clear", "acme"); err != nil || !strings.Contains(out, "free") || strings.Contains(out, "operator") {
		t.Fatalf("clear: %v\n%s", err, out)
	}
	if out, err := run("clear", "acme"); err != nil || !strings.Contains(out, "acme has no plan the operator set") {
		t.Errorf("clear again: %v\n%s", err, out)
	}
}
