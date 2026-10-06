package systemauth_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/oauthclient"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauth/storetest"
	"github.com/plexusone/systemforge/internal/pgtest"

	_ "github.com/mattn/go-sqlite3"
)

// openSQLite returns a migrated Ent client on a private in-memory SQLite
// database. One connection serializes access, as SQLite requires.
func openSQLite(t *testing.T) *ent.Client {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	return migrate(t, entsql.OpenDB(dialect.SQLite, db))
}

// openPostgres returns a migrated Ent client on a scratch PostgreSQL
// database, skipping when SF_TEST_PG_DSN is unset.
func openPostgres(t *testing.T) *ent.Client {
	t.Helper()
	return migrate(t, entsql.OpenDB(dialect.Postgres, pgtest.Open(t)))
}

func migrate(t *testing.T, drv *entsql.Driver) *ent.Client {
	t.Helper()
	client := ent.NewClient(ent.Driver(drv))
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	return client
}

type backend struct {
	name string
	open func(t *testing.T) *ent.Client
}

var entBackends = []backend{{"sqlite", openSQLite}, {"postgres", openPostgres}}

func TestLoginSessionStoreConformance(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		storetest.LoginSessionStore(t, func(*testing.T) systemauth.LoginSessionStore {
			return systemauth.NewMemoryLoginSessionStore()
		})
	})
	for _, b := range entBackends {
		t.Run("ent-"+b.name, func(t *testing.T) {
			client := b.open(t)
			storetest.LoginSessionStore(t, func(*testing.T) systemauth.LoginSessionStore {
				return systemauth.NewEntLoginSessionStore(client)
			})
		})
	}
}

func TestLoginStateStoreConformance(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		storetest.StateStore(t, func(*testing.T) oauthclient.StateStore {
			return oauthclient.NewMemoryStateStore()
		})
	})
	for _, b := range entBackends {
		t.Run("ent-"+b.name, func(t *testing.T) {
			client := b.open(t)
			storetest.StateStore(t, func(*testing.T) oauthclient.StateStore {
				return systemauth.NewEntLoginStateStore(client)
			})
		})
	}
}

func TestConsentStoreConformance(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		storetest.ConsentStore(t, func(*testing.T) systemauth.ConsentStore {
			return systemauth.NewMemoryConsentStore()
		})
	})
	for _, b := range entBackends {
		t.Run("ent-"+b.name, func(t *testing.T) {
			client := b.open(t)
			storetest.ConsentStore(t, func(*testing.T) systemauth.ConsentStore {
				return systemauth.NewEntConsentStore(client)
			})
		})
	}
}

// TestEntStoresSurviveRestart checks that a second store instance on the
// same database (a restarted or sibling replica) sees the first's state.
func TestEntStoresSurviveRestart(t *testing.T) {
	for _, b := range entBackends {
		t.Run(b.name, func(t *testing.T) {
			ctx := context.Background()
			client := b.open(t)
			now := time.Now()
			pid := uuid.New()
			if err := systemauth.NewEntLoginSessionStore(client).Create(ctx, "tok", systemauth.LoginSession{
				PrincipalID: pid, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
			}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			got, err := systemauth.NewEntLoginSessionStore(client).Get(ctx, "tok")
			if err != nil || got.PrincipalID != pid {
				t.Fatalf("Get from second instance = %+v, %v", got, err)
			}
			if err := systemauth.NewEntLoginStateStore(client).Put(ctx, "st", oauthclient.StateData{Provider: "github"}, time.Minute); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if _, err := systemauth.NewEntLoginStateStore(client).Take(ctx, "st"); err != nil {
				t.Fatalf("Take from second instance: %v", err)
			}
		})
	}
}

// TestEntLoginSessionStoreStoresOnlyHashes checks the raw token never
// reaches the database.
func TestEntLoginSessionStoreStoresOnlyHashes(t *testing.T) {
	ctx := context.Background()
	client := openSQLite(t)
	const tok = "raw-session-token-value"
	now := time.Now()
	if err := systemauth.NewEntLoginSessionStore(client).Create(ctx, tok, systemauth.LoginSession{
		PrincipalID: uuid.New(), CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	rows, err := client.LoginSession.Query().All(ctx)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 || rows[0].TokenHash == tok || len(rows[0].TokenHash) != 64 {
		t.Fatalf("stored token hash = %q", rows[0].TokenHash)
	}
}
