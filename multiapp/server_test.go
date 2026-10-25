package multiapp

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"entgo.io/ent"
	"github.com/go-chi/chi/v5"
)

// testBackend is an app whose migration creates an items table.
type testBackend struct {
	slug string
	deps Dependencies
}

func (b *testBackend) Slug() string             { return b.slug }
func (b *testBackend) Name() string             { return "Test " + b.slug }
func (b *testBackend) EntSchemas() []ent.Schema { return nil }
func (b *testBackend) Routes(deps Dependencies) chi.Router {
	b.deps = deps
	return chi.NewRouter()
}
func (b *testBackend) OnRegister(context.Context, *AppConfig) error { return nil }
func (b *testBackend) OnShutdown(context.Context) error             { return nil }
func (b *testBackend) Migrations() []Migration {
	return []Migration{{
		Version: 1,
		Name:    "items",
		Up: func(ctx context.Context, db *SchemaDB) error {
			_, err := db.Exec(ctx, "CREATE TABLE IF NOT EXISTS items (name text)")
			return err
		},
	}}
}

// syncBuffer is a log sink safe for concurrent writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func shutdownLater(t *testing.T, s *Server) {
	t.Cleanup(func() {
		if err := s.Shutdown(context.Background()); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
	})
}

func TestNewServerValidatesDatabaseConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"nothing":                    {},
		"skip check without opt-out": {SkipIsolationCheck: true, AppDatabases: map[string]AppDatabase{"x": {URL: "postgres://x@localhost/x"}}},
		"opt-out without login":      {AllowSharedDatabaseLogin: true},
		"empty app database":         {AppDatabases: map[string]AppDatabase{"x": {}}},
		"unsafe migration role":      {AppDatabases: map[string]AppDatabase{"x": {URL: "postgres://x@localhost/x"}}, MigrationRole: `bad"role`},
	} {
		if _, err := NewServer(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRegisterAppRequiresItsOwnLogin(t *testing.T) {
	f := newPGFixture(t)
	s, err := NewServer(Config{Mode: MultiAppMode, MigrationDatabaseURL: f.dsn, AllowInProcessMigrations: true})
	if err != nil {
		t.Fatal(err)
	}
	shutdownLater(t, s)
	err = s.RegisterApp(&testBackend{slug: "one"})
	if !errors.Is(err, ErrAppDatabaseLoginRequired) {
		t.Fatalf("RegisterApp without a login: %v, want ErrAppDatabaseLoginRequired", err)
	}
	if !strings.Contains(err.Error(), `AppDatabases["one"]`) || !strings.Contains(err.Error(), "AllowSharedDatabaseLogin") {
		t.Errorf("error does not say how to fix it: %v", err)
	}
	if len(s.Apps()) != 0 {
		t.Error("the app was registered")
	}
}

func TestSharedLoginOptOutWarns(t *testing.T) {
	f := newPGFixture(t)
	var logs syncBuffer
	s, err := NewServer(Config{
		Mode:                     MultiAppMode,
		MigrationDatabaseURL:     f.dsn,
		AllowSharedDatabaseLogin: true,
		Logger:                   slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	shutdownLater(t, s)
	one, two := &testBackend{slug: "one"}, &testBackend{slug: "two"}
	for _, b := range []*testBackend{one, two} {
		if err := s.RegisterApp(b); err != nil {
			t.Fatalf("RegisterApp(%s): %v", b.slug, err)
		}
	}
	if _, err := one.deps.DB.Exec(context.Background(), "INSERT INTO items VALUES ('x')"); err != nil {
		t.Fatalf("shared login: %v", err)
	}
	for _, want := range []string{"AllowSharedDatabaseLogin is set", "app uses the shared database login"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs lack %q:\n%s", want, logs.String())
		}
	}
	if err := s.VerifyDatabaseIsolation(context.Background()); err != nil {
		t.Errorf("shared apps have no login to check, got %v", err)
	}
}

func TestNewServerRefusesInProcessMigrationsByDefault(t *testing.T) {
	_, err := NewServer(Config{
		Mode:                 SingleAppMode,
		MigrationDatabaseURL: "postgres://owner@localhost/x",
		AppDatabases:         map[string]AppDatabase{"x": {URL: "postgres://x@localhost/x"}},
	})
	if !errors.Is(err, ErrInProcessMigrationsNotAllowed) {
		t.Fatalf("NewServer: %v, want ErrInProcessMigrationsNotAllowed", err)
	}
	if !strings.Contains(err.Error(), "multiapp.Migrate") || !strings.Contains(err.Error(), "AllowInProcessMigrations") {
		t.Errorf("error does not say how to fix it: %v", err)
	}
}

func TestInProcessMigrationsWarn(t *testing.T) {
	f := newPGFixture(t)
	owner, _ := f.provisionedApps("one")
	var logs syncBuffer
	s, err := NewServer(Config{
		Mode:                     SingleAppMode,
		MigrationDatabaseURL:     f.loginURL(owner),
		AllowInProcessMigrations: true,
		AppDatabases:             map[string]AppDatabase{"one": {URL: f.loginURL(f.name("sfapp_one"))}},
		Logger:                   slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	shutdownLater(t, s)
	one := &testBackend{slug: "one"}
	if err := s.RegisterApp(one); err != nil {
		t.Fatalf("RegisterApp: %v", err)
	}
	if !strings.Contains(logs.String(), "in-process migrations are enabled") {
		t.Errorf("no warning about in-process migrations:\n%s", logs.String())
	}
	if _, err := one.deps.DB.Exec(context.Background(), "INSERT INTO items VALUES ('x')"); err != nil {
		t.Fatalf("migrated table: %v", err)
	}
}

// TestRegisterAppRequiresTheSchemaWithoutMigrations starts a server
// without the migration login and expects an app whose schema was never
// created to be refused.
func TestRegisterAppRequiresTheSchemaWithoutMigrations(t *testing.T) {
	f := newPGFixture(t)
	owner, _ := f.provisionedApps("one")
	f.exec("DROP SCHEMA app_one CASCADE")
	s, err := NewServer(Config{
		Mode:          SingleAppMode,
		MigrationRole: owner,
		AppDatabases:  map[string]AppDatabase{"one": {URL: f.loginURL(f.name("sfapp_one"))}},
	})
	if err != nil {
		t.Fatal(err)
	}
	shutdownLater(t, s)
	err = s.RegisterApp(&testBackend{slug: "one"})
	if !errors.Is(err, ErrAppSchemaMissing) {
		t.Fatalf("RegisterApp: %v, want ErrAppSchemaMissing", err)
	}
	if !strings.Contains(err.Error(), `"app_one"`) || !strings.Contains(err.Error(), "multiapp.Migrate") {
		t.Errorf("error does not name the schema and the fix: %v", err)
	}
	if _, ok := s.GetApp("one"); ok {
		t.Error("the app was registered")
	}
}

// TestRegisterAppWithProvisionedLogins runs two apps on their own
// provisioned logins, migrated beforehand with Migrate and the owner
// login, as a production deployment does: the server holds no owner
// login.
func TestRegisterAppWithProvisionedLogins(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	owner, _ := f.provisionedApps("one", "two")
	one, two := &testBackend{slug: "one"}, &testBackend{slug: "two"}
	if err := Migrate(ctx, f.loginURL(owner), one, two); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	var logs syncBuffer
	s, err := NewServer(Config{
		Mode:          MultiAppMode,
		MigrationRole: owner,
		AppDatabases: map[string]AppDatabase{
			"one": {URL: f.loginURL(f.name("sfapp_one"))},
			"two": {URL: f.loginURL(f.name("sfapp_two"))},
		},
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	shutdownLater(t, s)
	for _, b := range []*testBackend{one, two} {
		if err := s.RegisterApp(b); err != nil {
			t.Fatalf("RegisterApp(%s): %v", b.slug, err)
		}
	}
	if err := s.VerifyDatabaseIsolation(ctx); err != nil {
		t.Fatalf("VerifyDatabaseIsolation: %v", err)
	}
	if strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("unexpected warning:\n%s", logs.String())
	}

	// Each app writes its own migrated table, and only its own.
	if _, err := one.deps.DB.Exec(ctx, "INSERT INTO items VALUES ('one')"); err != nil {
		t.Fatalf("own table: %v", err)
	}
	var user string
	if err := one.deps.DB.QueryRow(ctx, "SELECT current_user").Scan(&user); err != nil || user != f.name("sfapp_one") {
		t.Errorf("app one runs as %q, %v", user, err)
	}
	for _, stmt := range []string{
		"SELECT * FROM app_two.items",
		"INSERT INTO app_two.items VALUES ('x')",
		"SET LOCAL ROLE " + quoteIdent(f.name("sfapp_two")),
		"SET LOCAL ROLE " + quoteIdent(owner),
	} {
		if _, err := one.deps.DB.Exec(ctx, stmt); !isPermissionDenied(err) {
			t.Errorf("%s: %v, want permission denied", stmt, err)
		}
	}
	tx, err := one.deps.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SELECT * FROM app_two.items"); !isPermissionDenied(err) {
		t.Errorf("after RESET ROLE: %v, want permission denied", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// The app's pool serves its own schema only.
	if _, err := s.apps["one"].db.ForSchema("app_two"); !errors.Is(err, ErrSharedDatabaseLogin) {
		t.Errorf("app one's pool served app_two: %v", err)
	}
	// An Ent-style database/sql pool connects with the app's login.
	sqlDB, err := one.deps.DB.StdDB(ctx)
	if err != nil {
		t.Fatalf("StdDB: %v", err)
	}
	defer func() {
		if err := sqlDB.Close(); err != nil {
			t.Error(err)
		}
	}()
	var n int
	if err := sqlDB.QueryRowContext(ctx, "SELECT count(*) FROM items").Scan(&n); err != nil || n != 1 {
		t.Errorf("StdDB reads its own items: %d, %v", n, err)
	}
	if _, err := sqlDB.ExecContext(ctx, "SELECT * FROM app_two.items"); !isPermissionDenied(err) {
		t.Errorf("StdDB reads app_two: %v", err)
	}
}

// TestRegisterAppRefusesALeakyLogin registers one app, gives the second
// app's login access to the first app's schema, and expects the second
// registration to fail, naming the app and not the credentials.
func TestRegisterAppRefusesALeakyLogin(t *testing.T) {
	f := newPGFixture(t)
	owner, _ := f.provisionedApps("one", "two")
	twoRole := f.name("sfapp_two")
	f.exec("GRANT USAGE ON SCHEMA app_one TO " + quoteIdent(twoRole))
	s, err := NewServer(Config{
		Mode:                     SingleAppMode,
		MigrationDatabaseURL:     f.loginURL(owner),
		AllowInProcessMigrations: true,
		AppDatabases: map[string]AppDatabase{
			"one": {URL: f.loginURL(f.name("sfapp_one"))},
			"two": {URL: f.loginURL(twoRole)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	shutdownLater(t, s)
	if err := s.RegisterApp(&testBackend{slug: "one"}); err != nil {
		t.Fatalf("RegisterApp(one): %v", err)
	}
	err = s.RegisterApp(&testBackend{slug: "two"})
	var ie *IsolationError
	if !errors.As(err, &ie) {
		t.Fatalf("RegisterApp(two): %v, want an IsolationError", err)
	}
	if !strings.Contains(err.Error(), `app "two"`) || !strings.Contains(err.Error(), `USAGE on schema "app_one"`) {
		t.Errorf("error does not name the problem: %v", err)
	}
	if strings.Contains(err.Error(), "postgres://") {
		t.Errorf("error includes a connection string: %v", err)
	}
	if _, ok := s.GetApp("two"); ok {
		t.Error("the leaky app was registered")
	}
}
