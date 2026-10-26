package multiapp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ServerMode determines how the server handles app routing.
type ServerMode string

const (
	// MultiAppMode routes requests to apps based on X-App-ID header.
	// Multiple apps share the same server instance.
	MultiAppMode ServerMode = "multi"

	// SingleAppMode runs a single app without header-based routing.
	// The app owns the entire server instance.
	SingleAppMode ServerMode = "single"
)

// Config contains configuration for creating a new server.
//
// Every app connects to the database with a login of its own, given in
// AppDatabases, in single-app and multi-app mode alike. Schema and table
// changes run with a separate migration (owner) login, as a deploy step of
// their own (Migrate) in production, so the server process never holds the
// owner's credentials. See "Database isolation" in the package README.
type Config struct {
	// Mode determines how apps are routed (multi or single).
	Mode ServerMode

	// AppDatabases holds each app's own database login, keyed by app
	// slug. RegisterApp refuses an app without one unless
	// AllowSharedDatabaseLogin is set. Each login gets its own pool,
	// serves its app's schema only, and must pass the isolation check.
	AppDatabases map[string]AppDatabase

	// MigrationDatabaseURL is the migration (owner) login, for running
	// migrations in the server process: RegisterApp then uses it to create
	// each app's schema and run the app's Migrations. It is never handed
	// to app code. It is accepted only with AllowInProcessMigrations (or
	// AllowSharedDatabaseLogin). Leave it empty in production and run
	// Migrate as a separate step, such as a one-off task given the owner's
	// secret; RegisterApp then expects each app's schema to exist, refuses
	// an app whose schema is missing (ErrAppSchemaMissing), and does not
	// run Migrations.
	MigrationDatabaseURL string

	// AllowInProcessMigrations lets the server hold the migration login,
	// MigrationDatabaseURL, and create schemas and run migrations when an
	// app registers. Any code that takes over the process can then use
	// the owner's privileges on every app schema. For local development
	// only; the server logs a warning when it is set.
	AllowInProcessMigrations bool

	// MigrationRole names the migration (owner) role when
	// MigrationDatabaseURL is empty, so the isolation check can verify
	// that no app login is a member of it or can act as it. It holds no
	// credentials. With MigrationDatabaseURL, the role is read from that
	// login and this field is ignored. Optional, but set it in
	// production.
	MigrationRole string

	// AllowSharedDatabaseLogin lets apps without an AppDatabases entry
	// use the MigrationDatabaseURL login, shared by every such app. The
	// database then does not keep those apps apart: each can read and
	// write the others' tables. It needs MigrationDatabaseURL and implies
	// AllowInProcessMigrations, since the apps on it already hold the
	// owner login. For local development only; the server logs a warning
	// when it is set.
	AllowSharedDatabaseLogin bool

	// SkipIsolationCheck turns the database isolation check off. It is
	// accepted only together with AllowSharedDatabaseLogin. Apps on the
	// shared login are never checked as subjects either way.
	SkipIsolationCheck bool

	// RedisURL is the Redis connection string for caching and sessions.
	// Optional - if empty, an in-memory cache is used.
	RedisURL string

	// Logger is the logger to use. If nil, a default logger is created.
	Logger *slog.Logger
}

// AppDatabase is an app's own database login.
type AppDatabase struct {
	// URL is a PostgreSQL connection string with the app's own
	// credentials, for example read from a secret manager at startup.
	URL string

	// PoolConfig, when set, is used instead of URL: for example a config
	// whose BeforeConnect sets a short-lived IAM authentication token as
	// the password.
	PoolConfig *pgxpool.Config
}

// ErrAppDatabaseLoginRequired is returned when an app is registered
// without a database login of its own and the shared login is not allowed.
var ErrAppDatabaseLoginRequired = errors.New("multiapp: app has no database login of its own")

// ErrInProcessMigrationsNotAllowed is returned by NewServer when
// MigrationDatabaseURL is set without AllowInProcessMigrations.
var ErrInProcessMigrationsNotAllowed = errors.New("multiapp: MigrationDatabaseURL puts the migration (owner) login in the server process")

// ErrAppSchemaMissing is returned by RegisterApp when the server runs no
// migrations (no MigrationDatabaseURL) and the app's schema does not
// exist or its login cannot see it.
var ErrAppSchemaMissing = errors.New("multiapp: app schema does not exist")

// Server manages multiple app backends on shared or dedicated infrastructure.
type Server struct {
	config Config
	router *chi.Mux
	apps   map[string]*registeredApp
	// migrationDB is the migration (owner) login, or nil.
	migrationDB *AppAwareDB
	// ownerRole is the migration login's role name, when known.
	ownerRole string
	// sharedDB is the login apps share under AllowSharedDatabaseLogin.
	sharedDB *AppAwareDB
	cache    Cache
	logger   *slog.Logger
}

// registeredApp holds a registered app backend and its configuration.
type registeredApp struct {
	backend AppBackend
	config  *AppConfig
	router  chi.Router
	deps    Dependencies
	// db is the app's own login, nil for an app on the shared login.
	db *AppAwareDB
}

// NewServer creates a new multi-app server.
// The server does not require any external dependencies like SystemAuth.
func NewServer(cfg Config) (*Server, error) {
	if cfg.SkipIsolationCheck && !cfg.AllowSharedDatabaseLogin {
		return nil, errors.New("multiapp: SkipIsolationCheck requires AllowSharedDatabaseLogin")
	}
	if cfg.AllowSharedDatabaseLogin && cfg.MigrationDatabaseURL == "" {
		return nil, errors.New("multiapp: AllowSharedDatabaseLogin requires MigrationDatabaseURL, the login the apps share")
	}
	if cfg.MigrationDatabaseURL == "" && len(cfg.AppDatabases) == 0 {
		return nil, errors.New("multiapp: no database configured: set AppDatabases (one login per app), and run migrations with Migrate")
	}
	if cfg.MigrationDatabaseURL != "" && !cfg.AllowInProcessMigrations && !cfg.AllowSharedDatabaseLogin {
		return nil, fmt.Errorf("%w: run migrations as a separate step with multiapp.Migrate and leave MigrationDatabaseURL empty, or set AllowInProcessMigrations for local development", ErrInProcessMigrationsNotAllowed)
	}
	if cfg.MigrationRole != "" {
		if err := checkName("migration role", cfg.MigrationRole); err != nil {
			return nil, err
		}
	}
	for slug, d := range cfg.AppDatabases {
		if d.URL == "" && d.PoolConfig == nil {
			return nil, fmt.Errorf("multiapp: AppDatabases[%q] has neither URL nor PoolConfig", slug)
		}
	}

	// Initialize logger
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	s := &Server{
		config:    cfg,
		apps:      make(map[string]*registeredApp),
		logger:    logger,
		ownerRole: cfg.MigrationRole,
	}
	if cfg.MigrationDatabaseURL != "" {
		logger.Warn("multiapp: in-process migrations are enabled; the server holds the migration (owner) login. Use it for local development only, and run multiapp.Migrate as a separate step in production")
		db, err := NewAppAwareDB(cfg.MigrationDatabaseURL, AsMigrationLogin())
		if err != nil {
			return nil, fmt.Errorf("multiapp: failed to connect with the migration login: %w", err)
		}
		s.migrationDB = db
		if err := db.pool.QueryRow(context.Background(), "SELECT current_user").Scan(&s.ownerRole); err != nil {
			return nil, errors.Join(fmt.Errorf("multiapp: reading the migration login's role: %w", err), s.closeDatabases())
		}
	}
	if cfg.AllowSharedDatabaseLogin {
		logger.Warn("multiapp: AllowSharedDatabaseLogin is set; apps without their own database login share one, and the database does not keep them apart. Use it for local development only")
		db, err := NewAppAwareDB(cfg.MigrationDatabaseURL, AllowSharedLogin())
		if err != nil {
			return nil, errors.Join(fmt.Errorf("multiapp: failed to connect with the shared login: %w", err), s.closeDatabases())
		}
		s.sharedDB = db
	}
	if cfg.SkipIsolationCheck {
		logger.Warn("multiapp: SkipIsolationCheck is set; app database logins are not checked")
	}

	// Initialize cache
	if cfg.RedisURL != "" {
		cache, err := NewRedisCache(cfg.RedisURL)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("multiapp: failed to connect to Redis: %w", err), s.closeDatabases())
		}
		s.cache = cache
	} else {
		s.cache = NewMemoryCache()
	}

	// Create router with standard middleware
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second))
	s.router = router

	// Add app context middleware in multi-app mode
	if cfg.Mode == MultiAppMode {
		router.Use(s.appContextMiddleware())
	}

	return s, nil
}

// openAppDatabase opens the app's own login, or returns the shared one
// (with shared true) when the app has none and that is allowed.
func (s *Server) openAppDatabase(ctx context.Context, slug string) (db *AppAwareDB, shared bool, err error) {
	d, ok := s.config.AppDatabases[slug]
	if !ok {
		if !s.config.AllowSharedDatabaseLogin {
			return nil, false, fmt.Errorf("%w: set Config.AppDatabases[%q] to the app's own login (see \"Database isolation\" in the multiapp README), or set AllowSharedDatabaseLogin for local development",
				ErrAppDatabaseLoginRequired, slug)
		}
		s.logger.Warn("multiapp: app uses the shared database login", "app", slug)
		return s.sharedDB, true, nil
	}
	config := d.PoolConfig
	if config == nil {
		config, err = pgxpool.ParseConfig(d.URL)
		if err != nil {
			return nil, false, fmt.Errorf("multiapp: app %q: parsing its database URL: %w", slug, err)
		}
	}
	db, err = NewAppAwareDBWithConfig(ctx, config)
	if err != nil {
		return nil, false, fmt.Errorf("multiapp: app %q: connecting with its database login: %w", slug, err)
	}
	return db, false, nil
}

// RegisterApp registers an app backend with the server. It connects with
// the app's own database login, creates the app's schema and runs its
// migrations with the migration login when in-process migrations are
// enabled (otherwise it requires the schema to exist), and checks that the
// app's login is confined to its schema; any failure refuses the app.
func (s *Server) RegisterApp(backend AppBackend) error {
	ctx := context.Background()
	slug := backend.Slug()
	if slug == "" {
		return errors.New("multiapp: app slug cannot be empty")
	}
	if _, exists := s.apps[slug]; exists {
		return fmt.Errorf("multiapp: app %q already registered", slug)
	}
	schema := SchemaFromAppSlug(slug)
	if err := checkName("schema", schema); err != nil {
		return fmt.Errorf("multiapp: app %q: %w", slug, err)
	}

	appDB, shared, err := s.openAppDatabase(ctx, slug)
	if err != nil {
		return err
	}
	ownDB := appDB
	if shared {
		ownDB = nil
	}
	fail := func(err error) error {
		if ownDB != nil {
			return errors.Join(err, ownDB.Close())
		}
		return err
	}

	// Schema and migrations run with the migration login.
	if s.migrationDB != nil {
		if err := migrateApp(ctx, s.migrationDB, slug, schema, backend.Migrations()); err != nil {
			return fail(err)
		}
	} else {
		// Migrations ran as a separate step; the schema must exist.
		if err := requireSchema(ctx, appDB, slug, schema); err != nil {
			return fail(err)
		}
		if len(backend.Migrations()) > 0 {
			s.logger.Debug("multiapp: migrations run as a separate step (multiapp.Migrate)", "app", slug)
		}
	}

	if !shared && !s.config.SkipIsolationCheck {
		logins := append(s.isolationLogins(), AppDatabaseLogin{Slug: slug, Schema: schema, Pool: appDB.pool})
		if err := CheckDatabaseIsolation(ctx, logins, s.ownerRoles()...); err != nil {
			return fail(err)
		}
	}

	// Create app config
	appConfig := &AppConfig{
		AppID:          slug,
		Slug:           slug,
		DatabaseSchema: schema,
		Features:       []string{},
		Settings:       make(map[string]any),
	}

	// Create scoped dependencies
	schemaDB, err := appDB.ForSchema(schema)
	if err != nil {
		return fail(fmt.Errorf("multiapp: %w", err))
	}
	deps := Dependencies{
		DB:     schemaDB,
		Cache:  s.cache.WithPrefix(slug + ":"),
		Logger: s.logger.With("app", slug),
		Config: appConfig,
	}

	// Get app routes
	appRouter := backend.Routes(deps)

	// Store registered app
	s.apps[slug] = &registeredApp{
		backend: backend,
		config:  appConfig,
		router:  appRouter,
		deps:    deps,
		db:      ownDB,
	}

	// Mount routes based on mode
	if s.config.Mode == SingleAppMode {
		// In single-app mode, mount routes directly at root
		s.router.Mount("/", appRouter)
	}
	// In multi-app mode, routing is handled by the dispatcher middleware

	// Call OnRegister
	if err := backend.OnRegister(ctx, appConfig); err != nil {
		return fmt.Errorf("multiapp: OnRegister failed for %q: %w", slug, err)
	}

	s.logger.Info("app registered",
		"app", slug,
		"name", backend.Name(),
		"schema", schema,
		"mode", s.config.Mode,
		"own_database_login", !shared,
	)

	return nil
}

// requireSchema reports ErrAppSchemaMissing unless schema exists and the
// app's login has USAGE on it.
func requireSchema(ctx context.Context, db *AppAwareDB, slug, schema string) error {
	var ok bool
	if err := db.pool.QueryRow(ctx,
		// has_schema_privilege fails on a missing schema, so it is asked
		// only once the schema is known to exist.
		"SELECT CASE WHEN EXISTS (SELECT FROM pg_catalog.pg_namespace WHERE nspname = $1::text) THEN has_schema_privilege($1::text, 'USAGE') ELSE false END",
		schema).Scan(&ok); err != nil {
		return fmt.Errorf("multiapp: app %q: checking schema %q: %w", slug, schema, err)
	}
	if !ok {
		return fmt.Errorf("%w: app %q: schema %q is missing or its login has no USAGE on it; provision the login (multiappdb apply) and run multiapp.Migrate before starting the server",
			ErrAppSchemaMissing, slug, schema)
	}
	return nil
}

// isolationLogins lists the registered apps for the isolation check; apps
// on the shared login have no pool, so only their schemas are checked.
func (s *Server) isolationLogins() []AppDatabaseLogin {
	logins := make([]AppDatabaseLogin, 0, len(s.apps))
	for slug, app := range s.apps {
		l := AppDatabaseLogin{Slug: slug, Schema: app.config.DatabaseSchema}
		if app.db != nil {
			l.Pool = app.db.pool
		}
		logins = append(logins, l)
	}
	return logins
}

func (s *Server) ownerRoles() []string {
	if s.ownerRole == "" {
		return nil
	}
	return []string{s.ownerRole}
}

// VerifyDatabaseIsolation runs CheckDatabaseIsolation over every
// registered app with its own login. RegisterApp and Run call it; call it
// yourself before serving if you serve Router without Run. It returns nil
// when SkipIsolationCheck is set.
func (s *Server) VerifyDatabaseIsolation(ctx context.Context) error {
	if s.config.SkipIsolationCheck {
		return nil
	}
	return CheckDatabaseIsolation(ctx, s.isolationLogins(), s.ownerRoles()...)
}

// Migrate creates the schemas of backends and runs their Migrations with
// the migration (owner) login at migrationDatabaseURL. It is the
// production way to migrate: run it as a separate step before the servers
// start, from a process given the owner's secret (for example the app
// binary's own migrate command, run as a one-off task), and leave
// Config.MigrationDatabaseURL empty in the servers. Every migration runs
// on every call, so migrations must be idempotent.
func Migrate(ctx context.Context, migrationDatabaseURL string, backends ...AppBackend) error {
	db, err := NewAppAwareDB(migrationDatabaseURL, AsMigrationLogin())
	if err != nil {
		return fmt.Errorf("multiapp: failed to connect with the migration login: %w", err)
	}
	for _, b := range backends {
		schema := SchemaFromAppSlug(b.Slug())
		if err := migrateApp(ctx, db, b.Slug(), schema, b.Migrations()); err != nil {
			return errors.Join(err, db.Close())
		}
	}
	return db.Close()
}

// migrateApp creates schema and runs migrations in it with the migration
// login.
func migrateApp(ctx context.Context, db *AppAwareDB, slug, schema string, migrations []Migration) error {
	if err := db.CreateSchema(ctx, schema); err != nil {
		return fmt.Errorf("multiapp: failed to create schema for %q: %w", slug, err)
	}
	if len(migrations) == 0 {
		return nil
	}
	schemaDB, err := db.ForSchema(schema)
	if err != nil {
		return fmt.Errorf("multiapp: %w", err)
	}
	// TODO: Implement proper migration tracking
	// For now, just run all migrations
	for _, m := range migrations {
		if m.Up != nil {
			if err := m.Up(ctx, schemaDB); err != nil {
				return fmt.Errorf("multiapp: failed to run migrations for %q: migration %d (%s) failed: %w", slug, m.Version, m.Name, err)
			}
		}
	}
	return nil
}

// appContextMiddleware extracts app context from X-App-ID header and routes to the correct app.
// Returns generic 404 for missing/invalid app IDs to prevent information leakage.
func (s *Server) appContextMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract app ID from header
			// Return generic 404 for security - don't reveal routing mechanism or valid app IDs
			appID := r.Header.Get("X-App-ID")
			if appID == "" {
				http.NotFound(w, r)
				return
			}

			// Look up app from compiled-in registry (no external calls)
			// Return same 404 for unknown apps - prevents app ID enumeration
			app, ok := s.apps[appID]
			if !ok {
				http.NotFound(w, r)
				return
			}

			// Create app context
			appCtx := &AppContext{
				AppID:          app.config.AppID,
				AppSlug:        app.config.Slug,
				AppName:        app.backend.Name(),
				DatabaseSchema: app.config.DatabaseSchema,
				Features:       app.config.Features,
				Settings:       app.config.Settings,
			}

			// Add to request context
			ctx := WithAppContext(r.Context(), appCtx)

			// Route to app's router
			app.router.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Router returns the underlying chi router for custom middleware.
func (s *Server) Router() *chi.Mux {
	return s.router
}

// Apps returns the list of registered app slugs.
func (s *Server) Apps() []string {
	slugs := make([]string, 0, len(s.apps))
	for slug := range s.apps {
		slugs = append(slugs, slug)
	}
	return slugs
}

// GetApp returns a registered app by slug.
func (s *Server) GetApp(slug string) (AppBackend, bool) {
	app, ok := s.apps[slug]
	if !ok {
		return nil, false
	}
	return app.backend, true
}

// Run verifies database isolation, then starts the HTTP server and blocks
// until shutdown.
func (s *Server) Run(addr string) error {
	if err := s.VerifyDatabaseIsolation(context.Background()); err != nil {
		return err
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Channel to listen for shutdown signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Channel to listen for server errors
	serverErr := make(chan error, 1)

	// Start server in goroutine
	go func() {
		s.logger.Info("server starting",
			"addr", addr,
			"mode", s.config.Mode,
			"apps", len(s.apps),
		)
		serverErr <- server.ListenAndServe()
	}()

	// Wait for shutdown signal or server error
	select {
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server error: %w", err)
		}
	case <-shutdown:
		s.logger.Info("shutdown signal received")
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Call OnShutdown for all apps
	s.shutdownApps(ctx)

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}

	// Close database
	if err := s.closeDatabases(); err != nil {
		s.logger.Error("database close error", "error", err)
	}

	s.logger.Info("server stopped")
	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownApps(ctx)
	if err := s.closeDatabases(); err != nil {
		return fmt.Errorf("database close error: %w", err)
	}
	return nil
}

// shutdownApps calls OnShutdown for all apps.
func (s *Server) shutdownApps(ctx context.Context) {
	for slug, app := range s.apps {
		if err := app.backend.OnShutdown(ctx); err != nil {
			s.logger.Error("app shutdown error", "app", slug, "error", err)
		}
	}
}

// closeDatabases closes every pool the server opened.
func (s *Server) closeDatabases() error {
	var errs []error
	for _, app := range s.apps {
		if app.db != nil {
			errs = append(errs, app.db.Close())
		}
	}
	for _, db := range []*AppAwareDB{s.sharedDB, s.migrationDB} {
		if db != nil {
			errs = append(errs, db.Close())
		}
	}
	return errors.Join(errs...)
}
