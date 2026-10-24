package multiapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// EntConfig provides configuration for Ent client creation.
type EntConfig struct {
	// Schema is the PostgreSQL schema name for this app.
	Schema string

	// Debug enables Ent debug logging.
	Debug bool
}

// EntClientFactory creates Ent clients scoped to app schemas.
// This bridges the multiapp SchemaDB with Ent's database layer.
type EntClientFactory struct {
	db *AppAwareDB
}

// NewEntClientFactory creates a factory for app-scoped Ent clients.
func NewEntClientFactory(db *AppAwareDB) *EntClientFactory {
	return &EntClientFactory{db: db}
}

// StdDBForSchema returns a *sql.DB configured for a specific schema.
// Every connection of the returned pool has search_path set to the app's
// schema, so the pool must serve that app only. The schema name must be a
// plain identifier (see AppAwareDB.ForSchema); anything else is refused.
//
// Usage with Ent:
//
//	factory := multiapp.NewEntClientFactory(appAwareDB)
//	db, err := factory.StdDBForSchema(ctx, "app_app1")
//	if err != nil {
//	    return err
//	}
//	drv := entsql.OpenDB(dialect.Postgres, db)
//	client := ent.NewClient(ent.Driver(drv))
func (f *EntClientFactory) StdDBForSchema(ctx context.Context, schema string) (*sql.DB, error) {
	if !isValidSchemaName(schema) {
		return nil, fmt.Errorf("multiapp: invalid schema name %q", schema)
	}
	// Get connection config from pool
	config := f.db.pool.Config().ConnConfig.Copy()

	// Add search_path to connection parameters
	// This ensures all connections from this pool use the correct schema
	if config.RuntimeParams == nil {
		config.RuntimeParams = make(map[string]string)
	}
	config.RuntimeParams["search_path"] = schema + ", public"

	// Create a new connection string with the modified config
	connStr := stdlib.RegisterConnConfig(config)

	// Open standard database connection
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		return nil, fmt.Errorf("multiapp: failed to open database for schema %s: %w", schema, err)
	}

	// Verify connection
	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("multiapp: failed to ping database for schema %s: %w", schema, err), db.Close())
	}

	return db, nil
}

// EntDriverForSchema returns an Ent SQL driver scoped to a schema.
// This is a convenience wrapper around StdDBForSchema.
//
// Usage:
//
//	drv, err := factory.EntDriverForSchema(ctx, "app_app1")
//	client := ent.NewClient(ent.Driver(drv))
func (f *EntClientFactory) EntDriverForSchema(ctx context.Context, schema string) (*entsql.Driver, error) {
	db, err := f.StdDBForSchema(ctx, schema)
	if err != nil {
		return nil, err
	}
	return entsql.OpenDB(dialect.Postgres, db), nil
}

// SchemaFromAppSlug returns the database schema name for an app slug.
// By convention, app schemas are named "app_{slug}".
func SchemaFromAppSlug(slug string) string {
	return "app_" + slug
}

// EntConnHook sets an application's schema on database/sql transactions,
// from the AppContext in the request context.
type EntConnHook struct {
	db *AppAwareDB
}

// NewEntConnHook creates a new Ent connection hook.
func NewEntConnHook(db *AppAwareDB) *EntConnHook {
	return &EntConnHook{db: db}
}

// schemaFromContext returns the validated schema of the AppContext in ctx.
func schemaFromContext(ctx context.Context) (string, error) {
	appCtx := AppContextFromContext(ctx)
	if appCtx == nil {
		return "", ErrNoAppContext
	}
	schema := appCtx.DatabaseSchema
	if schema == "" {
		return "", fmt.Errorf("multiapp: app context has no database schema")
	}
	if !isValidSchemaName(schema) {
		return "", fmt.Errorf("multiapp: invalid schema name %q", schema)
	}
	return schema, nil
}

// SetSchemaInTx scopes tx to the schema of the AppContext in ctx with SET
// LOCAL search_path, which ends with the transaction, so the connection
// goes back to the pool without it. Call it first in every transaction an
// application runs.
func (h *EntConnHook) SetSchemaInTx(ctx context.Context, tx *sql.Tx) error {
	schema, err := schemaFromContext(ctx)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL search_path TO %s, public", schema)); err != nil {
		return fmt.Errorf("multiapp: failed to set search_path: %w", err)
	}
	return nil
}

// SetSchemaFromContext sets the search_path of conn to the schema of the
// AppContext in ctx, for the whole session.
//
// Deprecated: the setting stays on the connection after it returns to the
// database/sql pool, so later use of that connection by code that does not
// run the hook reads and writes this application's tables. Use
// SetSchemaInTx, whose search_path ends with the transaction.
func (h *EntConnHook) SetSchemaFromContext(ctx context.Context, conn *sql.Conn) error {
	schema, err := schemaFromContext(ctx)
	if err != nil {
		return err
	}

	_, err = conn.ExecContext(ctx, fmt.Sprintf("SET search_path TO %s, public", schema))
	if err != nil {
		return fmt.Errorf("multiapp: failed to set search_path: %w", err)
	}

	return nil
}

// PgxConnWithSchema opens a dedicated, unpooled pgx connection with schema
// set, for raw pgx operations outside of Ent; close it when done. The
// schema name must be a plain identifier; anything else is refused.
func (f *EntClientFactory) PgxConnWithSchema(ctx context.Context, schema string) (*pgx.Conn, error) {
	if !isValidSchemaName(schema) {
		return nil, fmt.Errorf("multiapp: invalid schema name %q", schema)
	}
	config := f.db.pool.Config().ConnConfig.Copy()
	if config.RuntimeParams == nil {
		config.RuntimeParams = make(map[string]string)
	}
	config.RuntimeParams["search_path"] = schema + ", public"

	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("multiapp: failed to connect with schema %s: %w", schema, err)
	}

	return conn, nil
}
