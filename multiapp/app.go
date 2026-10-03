// Package multiapp provides infrastructure for running multiple apps on shared
// or dedicated backend infrastructure. Each app implements the AppBackend interface
// and is fully self-contained with its own users, organizations, and data.
//
// Apps can be deployed in two modes:
//   - Multi-app mode: Multiple apps share a server, routed by X-App-ID header
//   - Single-app mode: One app runs on dedicated infrastructure
//
// SystemAuth integration is optional - apps work without any external dependencies.
package multiapp

import (
	"context"
	"log/slog"

	"entgo.io/ent"
	"github.com/go-chi/chi/v5"
)

// AppBackend is the interface that all app backends must implement.
// This enables composition of multiple apps into a single server or
// standalone deployment on dedicated infrastructure.
//
// Each app is self-contained with its own users, organizations, and data.
// No external dependencies (like SystemAuth) are required.
type AppBackend interface {
	// Slug returns the unique app identifier (e.g., "app1").
	// This is used for routing, database schema naming, and configuration.
	Slug() string

	// Name returns the human-readable display name (e.g., "App1").
	Name() string

	// EntSchemas returns the Ent schemas for this app's database tables.
	// These are created in the app's isolated database schema.
	EntSchemas() []ent.Schema

	// Routes returns the HTTP routes for this app.
	// Routes are mounted under the app's context with no prefix needed.
	// The Dependencies provide access to the database, cache, and logger.
	Routes(deps Dependencies) chi.Router

	// Migrations returns app-specific database migrations.
	// These run in the app's isolated database schema.
	Migrations() []Migration

	// OnRegister is called when the app is registered with the server.
	// Use this for app-specific initialization.
	OnRegister(ctx context.Context, cfg *AppConfig) error

	// OnShutdown is called when the server is shutting down.
	// Use this to clean up app-specific resources.
	OnShutdown(ctx context.Context) error
}

// Dependencies provides access to shared infrastructure for app handlers.
// All dependencies are scoped to the app's context.
type Dependencies struct {
	// DB provides database access scoped to the app's schema.
	DB *SchemaDB

	// Cache provides cache access with app-specific key prefix.
	Cache Cache

	// Logger is configured with app context (app slug, etc.).
	Logger *slog.Logger

	// Config contains app-specific configuration.
	Config *AppConfig
}

// AppConfig contains configuration for an app instance.
type AppConfig struct {
	// AppID is the unique identifier for this app (usually same as Slug).
	AppID string

	// Slug is the URL-safe identifier used for routing and schema naming.
	Slug string

	// DatabaseSchema is the PostgreSQL schema name for this app (e.g., "app_app1").
	DatabaseSchema string

	// Features lists enabled features for this app.
	Features []string

	// Settings contains app-specific configuration values.
	Settings map[string]any
}

// Migration represents a database migration for an app.
type Migration struct {
	// Version is the migration version number (must be unique and sequential).
	Version int

	// Name is a short description of the migration.
	Name string

	// Up applies the migration.
	Up func(ctx context.Context, db *SchemaDB) error

	// Down rolls back the migration (optional).
	Down func(ctx context.Context, db *SchemaDB) error
}

// Cache provides a cache interface for apps.
// Implementations can use Redis, in-memory, or other backends.
type Cache interface {
	// Get retrieves a value from the cache.
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores a value in the cache with optional TTL.
	Set(ctx context.Context, key string, value []byte, ttlSeconds int) error

	// Delete removes a value from the cache.
	Delete(ctx context.Context, key string) error

	// WithPrefix returns a Cache that prefixes all keys.
	WithPrefix(prefix string) Cache
}
