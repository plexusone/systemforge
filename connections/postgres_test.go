package connections_test

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	cf "github.com/plexusone/connectforge"
	"github.com/plexusone/connectforge/sqlstore"

	"github.com/plexusone/systemforge/connections"
	"github.com/plexusone/systemforge/internal/pgtest"
	"github.com/plexusone/systemforge/rls"
)

// TestRowLevelSecurityIsolatesOrganizations runs the store as an ordinary
// role, which row-level security applies to, and checks that the database
// itself refuses another organization's rows, not only the store's filters.
func TestRowLevelSecurityIsolatesOrganizations(t *testing.T) {
	ctx := context.Background()
	dsn := pgtest.DSN(t)
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Error(err)
		}
	})
	migrator := open(t, connections.Options{DB: admin, Dialect: sqlstore.Postgres})

	role := "sf_conn_app_" + uuid.NewString()[:8]
	stmts := []string{"CREATE ROLE " + role + " NOLOGIN", "GRANT USAGE ON SCHEMA public TO " + role}
	for _, tbl := range append(migrator.Store.Tables(), sqlstore.LeaseTable) {
		stmts = append(stmts, "GRANT SELECT, INSERT, UPDATE, DELETE ON "+tbl+" TO "+role)
	}
	stmts = append(stmts, "GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO "+role)
	for _, s := range stmts {
		if _, err := admin.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	t.Cleanup(func() {
		for _, s := range []string{"DROP OWNED BY " + role, "DROP ROLE " + role} {
			if _, err := admin.Exec(s); err != nil {
				t.Error(err)
			}
		}
	})

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("options", "-crole="+role)
	u.RawQuery = q.Encode()
	appDB, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := appDB.Close(); err != nil {
			t.Error(err)
		}
	})
	app, err := connections.Open(connections.Options{DB: appDB, Dialect: sqlstore.Postgres, Keys: openKeys(t), Authorizer: &fakeAuthz{}})
	if err != nil {
		t.Fatal(err)
	}

	orgA, orgB := uuid.New(), uuid.New()
	ctxA := rls.ContextWithTenant(ctx, orgA)
	now := time.Now().UTC()
	conn := func(org uuid.UUID) cf.Connection {
		return cf.Connection{
			ID: uuid.NewString(), Owner: connections.OwnerFor(org), Provider: "cloudflare",
			State: cf.StatePending, CreatedAt: now, UpdatedAt: now,
		}
	}

	a, err := app.Store.CreateConnection(ctxA, conn(orgA))
	if err != nil {
		t.Fatalf("own organization: %v", err)
	}
	if _, err := app.Store.GetConnection(ctxA, a.Owner, a.ID); err != nil {
		t.Fatalf("read own: %v", err)
	}

	// Writing a row for another organization is refused by the policy's
	// WITH CHECK, even though the store would have accepted it.
	if _, err := app.Store.CreateConnection(ctxA, conn(orgB)); err == nil {
		t.Fatal("wrote another organization's row")
	}

	// A row of organization B, written with B's context, is invisible to A
	// even when A asks for it by B's owner.
	b, err := app.Store.CreateConnection(rls.ContextWithTenant(ctx, orgB), conn(orgB))
	if err != nil {
		t.Fatalf("organization B: %v", err)
	}
	if _, err := app.Store.GetConnection(ctxA, b.Owner, b.ID); !errors.Is(err, cf.ErrNotFound) {
		t.Fatalf("read across organizations: %v", err)
	}
	if list, err := app.Store.ListConnections(ctxA, b.Owner, cf.Filter{}); err != nil || len(list) != 0 {
		t.Fatalf("list across organizations: %v, %v", list, err)
	}

	if _, err := app.Store.GetConnection(ctx, a.Owner, a.ID); !errors.Is(err, connections.ErrNoTenant) {
		t.Fatalf("no organization in context: %v", err)
	}
}
