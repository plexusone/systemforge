package connections_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3" // registers the "sqlite3" driver
	cf "github.com/plexusone/connectionforge"
	"github.com/plexusone/connectionforge/cryptotest"
	"github.com/plexusone/connectionforge/sqlstore"
	"github.com/plexusone/connectionforge/store/storetest"
	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/provider/local"
	"github.com/plexusone/omnivault/providers/memory"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/connections"
	sfaudit "github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/keys"
)

func openKeys(t *testing.T) *keys.Keys {
	t.Helper()
	root := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, local.RootKeySize))
	k, err := keys.Open(context.Background(), keys.Options{
		Dir:      t.TempDir(),
		Root:     keys.VaultSource(memory.NewWithSecrets(map[string]string{"root": root}), "root"),
		Purposes: []keyforge.Purpose{connections.Purpose},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := k.Close(); err != nil {
			t.Error(err)
		}
	})
	return k
}

func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "sf.db")+"?_fk=1&_txlock=immediate&_busy_timeout=10000")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return db
}

// fakeAuthz allows exactly the recorded (principal, permission) pairs and
// remembers the last question.
type fakeAuthz struct {
	allow map[string]bool
	last  struct {
		p authz.Principal
		a authz.Action
		r authz.Resource
	}
	err error
}

func (f *fakeAuthz) Can(_ context.Context, p authz.Principal, a authz.Action, r authz.Resource) (bool, error) {
	f.last.p, f.last.a, f.last.r = p, a, r
	return f.allow[p.ID.String()+"/"+string(a)], f.err
}

func (f *fakeAuthz) CanAll(ctx context.Context, p authz.Principal, as []authz.Action, r authz.Resource) (bool, error) {
	for _, a := range as {
		if ok, err := f.Can(ctx, p, a, r); err != nil || !ok {
			return false, err
		}
	}
	return true, nil
}

func (f *fakeAuthz) CanAny(ctx context.Context, p authz.Principal, as []authz.Action, r authz.Resource) (bool, error) {
	for _, a := range as {
		if ok, err := f.Can(ctx, p, a, r); err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

func (f *fakeAuthz) Filter(context.Context, authz.Principal, authz.Action, []authz.Resource) ([]authz.Resource, error) {
	return nil, errors.New("not used")
}

func open(t *testing.T, o connections.Options) *connections.Connections {
	t.Helper()
	if o.DB == nil {
		o.DB, o.Dialect = openSQLite(t), sqlstore.SQLite
	}
	if o.Keys == nil {
		o.Keys = openKeys(t)
	}
	if o.Authorizer == nil {
		o.Authorizer = &fakeAuthz{}
	}
	c, err := connections.Open(o)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStoreConformanceOnThePlatformDatabase(t *testing.T) {
	storetest.Run(t, func(t *testing.T) cf.Store { return open(t, connections.Options{}).Store })
}

func TestCredentialsAreSealedByKeys(t *testing.T) {
	cryptotest.Run(t, open(t, connections.Options{}).Crypto)
}

func TestAuthorizerMapsOntoResourcePermissions(t *testing.T) {
	ctx := context.Background()
	user, conn, org := uuid.New(), uuid.New(), uuid.New()
	az := &fakeAuthz{allow: map[string]bool{
		user.String() + "/" + string(authz.PermResourceEdit): true,
	}}
	c := open(t, connections.Options{Authorizer: az})
	p := cf.Principal{Kind: cf.PrincipalAgent, ID: user.String()}
	target := cf.Connection{ID: conn.String(), Owner: connections.OwnerFor(org)}

	if err := c.Authorizer.Allowed(ctx, p, cf.ActionUse, target); err != nil {
		t.Fatalf("use: %v", err)
	}
	if az.last.r.Type != connections.ResourceType || *az.last.r.ID != conn || *az.last.r.OrgID != org {
		t.Fatalf("resource: %+v", az.last.r)
	}
	if az.last.p.Type != connections.PrincipalTypeAgent {
		t.Fatalf("principal type: %s", az.last.p.Type)
	}
	for act, perm := range map[cf.Action]authz.Action{
		cf.ActionView:       authz.PermResourceView,
		cf.ActionManage:     authz.PermResourceManage,
		cf.ActionShare:      authz.PermResourceManage,
		cf.ActionDisconnect: authz.PermResourceManage,
	} {
		if err := c.Authorizer.Allowed(ctx, p, act, target); !errors.Is(err, cf.ErrDenied) {
			t.Errorf("%s: %v", act, err)
		}
		if az.last.a != perm {
			t.Errorf("%s asked for %s, want %s", act, az.last.a, perm)
		}
	}
	for name, bad := range map[string]struct {
		p cf.Principal
		c cf.Connection
	}{
		"principal":  {cf.Principal{ID: "alice"}, target},
		"connection": {p, cf.Connection{ID: "c1", Owner: target.Owner}},
		"owner":      {p, cf.Connection{ID: conn.String(), Owner: "acme"}},
	} {
		if err := c.Authorizer.Allowed(ctx, bad.p, cf.ActionUse, bad.c); !errors.Is(err, cf.ErrDenied) {
			t.Errorf("non-platform %s: %v", name, err)
		}
	}
	az.err = errors.New("backend down")
	if err := c.Authorizer.Allowed(ctx, p, cf.ActionUse, target); err == nil || errors.Is(err, cf.ErrDenied) {
		t.Errorf("backend failure should be an error, not a denial: %v", err)
	}
}

func TestEventsReachTheAuditTrail(t *testing.T) {
	ctx := context.Background()
	store := sfaudit.NewMemoryStore(10)
	c := open(t, connections.Options{Audit: store})
	org, conn, user := uuid.New(), uuid.New(), uuid.New()
	err := c.Auditor.Record(ctx, cf.Event{
		Time: time.Now(), Type: cf.EventConnectionCreated, Owner: connections.OwnerFor(org),
		Actor: cf.Principal{Kind: cf.PrincipalUser, ID: user.String()}, ConnectionID: conn.String(),
		Provider: "cloudflare", Success: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	evs, err := store.GetBySequence(ctx, 0, 10)
	if err != nil || len(evs) != 1 {
		t.Fatalf("events: %v, %v", evs, err)
	}
	e := evs[0]
	if e.Action != string(cf.EventConnectionCreated) || e.Outcome != "success" || e.Actor.ID != user ||
		e.Resource.ID != conn || e.Context.TenantID == nil || *e.Context.TenantID != org || e.Details["provider"] != "cloudflare" {
		t.Fatalf("event: %+v", e)
	}
}

func TestDeploymentSecretsComeFromTheVault(t *testing.T) {
	ctx := context.Background()
	c := open(t, connections.Options{Vault: memory.NewWithSecrets(map[string]string{"github/app-key": "pem"})})
	s, err := c.Secrets.Secret(ctx, "github/app-key")
	if err != nil || string(s.Reveal()) != "pem" {
		t.Fatalf("secret: %v", err)
	}
	if fmt.Sprint(s) == "pem" {
		t.Fatal("secret printed its value")
	}
	if _, err := c.Secrets.Secret(ctx, "missing"); err == nil {
		t.Fatal("missing secret")
	}
	none := open(t, connections.Options{})
	if _, err := none.Secrets.Secret(ctx, "x"); !errors.Is(err, connections.ErrNoVault) {
		t.Fatalf("no vault: %v", err)
	}
}

func TestOptionsAreRequired(t *testing.T) {
	db := openSQLite(t)
	k := openKeys(t)
	for name, o := range map[string]connections.Options{
		"db":         {Dialect: sqlstore.SQLite, Keys: k, Authorizer: &fakeAuthz{}},
		"keys":       {DB: db, Dialect: sqlstore.SQLite, Authorizer: &fakeAuthz{}},
		"authorizer": {DB: db, Dialect: sqlstore.SQLite, Keys: k},
		"dialect":    {DB: db, Dialect: "mysql", Keys: k, Authorizer: &fakeAuthz{}},
	} {
		if _, err := connections.Open(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
