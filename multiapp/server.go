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
type Config struct {
	// Mode determines how apps are routed (multi or single).
	Mode ServerMode

	// DatabaseURL is the PostgreSQL connection string.
	// In multi-app mode, each app gets its own schema within this database.
	DatabaseURL string

	// RedisURL is the Redis connection string for caching and sessions.
	// Optional - if empty, an in-memory cache is used.
	RedisURL string

	// Logger is the logger to use. If nil, a default logger is created.
	Logger *slog.Logger
}

// Server manages multiple app backends on shared or dedicated infrastructure.
type Server struct {
	config Config
	router *chi.Mux
	apps   map[string]*registeredApp
	db     *AppAwareDB
	cache  Cache
	logger *slog.Logger
}

// registeredApp holds a registered app backend and its configuration.
type registeredApp struct {
	backend AppBackend
	config  *AppConfig
	router  chi.Router
	deps    Dependencies
}

// NewServer creates a new multi-app server.
// The server does not require any external dependencies like SystemAuth.
func NewServer(cfg Config) (*Server, error) {
	if cfg.DatabaseURL == "" {
		return nil, errors.New("multiapp: DatabaseURL is required")
	}

	// Initialize logger
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	// Initialize database
	db, err := NewAppAwareDB(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("multiapp: failed to connect to database: %w", err)
	}

	// Initialize cache
	var cache Cache
	if cfg.RedisURL != "" {
		cache, err = NewRedisCache(cfg.RedisURL)
		if err != nil {
			return nil, fmt.Errorf("multiapp: failed to connect to Redis: %w", err)
		}
	} else {
		cache = NewMemoryCache()
	}

	// Create router with standard middleware
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(60 * time.Second))

	s := &Server{
		config: cfg,
		router: router,
		apps:   make(map[string]*registeredApp),
		db:     db,
		cache:  cache,
		logger: logger,
	}

	// Add app context middleware in multi-app mode
	if cfg.Mode == MultiAppMode {
		router.Use(s.appContextMiddleware())
	}

	return s, nil
}

// RegisterApp registers an app backend with the server.
// This creates the app's database schema and runs migrations.
func (s *Server) RegisterApp(backend AppBackend) error {
	slug := backend.Slug()
	if slug == "" {
		return errors.New("multiapp: app slug cannot be empty")
	}

	if _, exists := s.apps[slug]; exists {
		return fmt.Errorf("multiapp: app %q already registered", slug)
	}

	// Create database schema for this app
	schema := fmt.Sprintf("app_%s", slug)
	if err := s.db.CreateSchema(context.Background(), schema); err != nil {
		return fmt.Errorf("multiapp: failed to create schema for %q: %w", slug, err)
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
	schemaDB := s.db.ForSchema(schema)
	deps := Dependencies{
		DB:     schemaDB,
		Cache:  s.cache.WithPrefix(slug + ":"),
		Logger: s.logger.With("app", slug),
		Config: appConfig,
	}

	// Run migrations
	migrations := backend.Migrations()
	if len(migrations) > 0 {
		if err := s.runMigrations(schemaDB, migrations); err != nil {
			return fmt.Errorf("multiapp: failed to run migrations for %q: %w", slug, err)
		}
	}

	// Get app routes
	appRouter := backend.Routes(deps)

	// Store registered app
	s.apps[slug] = &registeredApp{
		backend: backend,
		config:  appConfig,
		router:  appRouter,
		deps:    deps,
	}

	// Mount routes based on mode
	if s.config.Mode == SingleAppMode {
		// In single-app mode, mount routes directly at root
		s.router.Mount("/", appRouter)
	}
	// In multi-app mode, routing is handled by the dispatcher middleware

	// Call OnRegister
	if err := backend.OnRegister(context.Background(), appConfig); err != nil {
		return fmt.Errorf("multiapp: OnRegister failed for %q: %w", slug, err)
	}

	s.logger.Info("app registered",
		"app", slug,
		"name", backend.Name(),
		"schema", schema,
		"mode", s.config.Mode,
	)

	return nil
}

// runMigrations runs migrations for an app.
func (s *Server) runMigrations(db *SchemaDB, migrations []Migration) error {
	// TODO: Implement proper migration tracking
	// For now, just run all migrations
	ctx := context.Background()
	for _, m := range migrations {
		if m.Up != nil {
			if err := m.Up(ctx, db); err != nil {
				return fmt.Errorf("migration %d (%s) failed: %w", m.Version, m.Name, err)
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

// Run starts the HTTP server and blocks until shutdown.
func (s *Server) Run(addr string) error {
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
	for slug, app := range s.apps {
		if err := app.backend.OnShutdown(ctx); err != nil {
			s.logger.Error("app shutdown error", "app", slug, "error", err)
		}
	}

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown error: %w", err)
	}

	// Close database
	if err := s.db.Close(); err != nil {
		s.logger.Error("database close error", "error", err)
	}

	s.logger.Info("server stopped")
	return nil
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	// Call OnShutdown for all apps
	for slug, app := range s.apps {
		if err := app.backend.OnShutdown(ctx); err != nil {
			s.logger.Error("app shutdown error", "app", slug, "error", err)
		}
	}

	// Close database
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("database close error: %w", err)
	}

	return nil
}
