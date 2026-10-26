package rls_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/rls"
)

const injected = `t; DROP TABLE x; --`

// Table, column, policy and role names are quoted identifiers and the
// session variable is a string literal, so none of them is read as SQL.
func TestGeneratedSQLQuotesNames(t *testing.T) {
	cfg := &rls.Config{
		TenantColumn:        `org"id`,
		SessionVariable:     `app.x', true) OR true OR current_setting('y`,
		UserSessionVariable: "app.current_user",
	}
	p := rls.NewPolicySQL(injected, "p", cfg)
	for name, stmt := range map[string]string{
		"all":    p.CreateAllPolicies(),
		"drop":   p.DropAllPolicies(),
		"bypass": rls.BypassRLS(injected),
		"revoke": rls.NoBypassRLS(injected),
	} {
		if strings.Contains(stmt, "TABLE x;") && !strings.Contains(stmt, `"t; DROP TABLE x; --"`) {
			t.Errorf("%s: unquoted table name in %s", name, stmt)
		}
		if strings.Contains(stmt, "OR true OR current_setting('y'") {
			t.Errorf("%s: session variable read as SQL in %s", name, stmt)
		}
	}
	if got := p.CreateSelectPolicy(); !strings.Contains(got, `"org""id"::text = current_setting('app.x'', true) OR true OR current_setting(''y', true)`) {
		t.Errorf("select policy = %s", got)
	}

	m := rls.NewMigrator(nil, &rls.MigrationConfig{
		Tables:          []string{"public." + injected},
		TenantColumn:    "organization_id",
		SessionVariable: "app.current_tenant",
		BypassRoles:     []string{"admin; DROP ROLE x"},
	})
	got := m.GenerateMigrationSQL() + m.GenerateRollbackSQL()
	if !strings.Contains(got, `ALTER TABLE "public"."t; DROP TABLE x; --" ENABLE ROW LEVEL SECURITY;`) {
		t.Errorf("migration SQL does not quote the table:\n%s", got)
	}
	if !strings.Contains(got, `ALTER ROLE "admin; DROP ROLE x" BYPASSRLS;`) {
		t.Errorf("migration SQL does not quote the role:\n%s", got)
	}
	if strings.Contains(got, "\nDROP TABLE") || strings.Contains(got, " DROP ROLE x;") {
		t.Errorf("injected statement in migration SQL:\n%s", got)
	}
}

// ClearContext runs RESET, which takes no bind parameter, so it refuses a
// session variable name that is not a plain parameter name.
func TestClearContextRefusesUnsafeNames(t *testing.T) {
	h := rls.NewHelper(&rls.Config{SessionVariable: "app.x; DROP TABLE y", UserSessionVariable: "app.current_user"})
	if err := h.ClearContext(context.Background(), refuseExec{t}); err == nil {
		t.Error("ClearContext accepted an unsafe session variable name")
	}
}

// refuseExec fails the test if any statement reaches it.
type refuseExec struct{ t *testing.T }

func (r refuseExec) ExecContext(_ context.Context, query string, _ ...any) (sql.Result, error) {
	r.t.Errorf("statement executed: %s", query)
	return nil, nil
}
