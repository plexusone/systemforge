package multiapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AppAwareDB manages database connections with schema-per-app isolation.
// Each app gets its own PostgreSQL schema. All schemas share one pool and
// database role, so the separation is by name, not a privilege boundary:
// see "Isolation limits" in the package README.
type AppAwareDB struct {
	pool    *pgxpool.Pool
	schemas map[string]*SchemaDB
	mu      sync.RWMutex
}

// NewAppAwareDB creates a new app-aware database connection pool.
func NewAppAwareDB(databaseURL string) (*AppAwareDB, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &AppAwareDB{
		pool:    pool,
		schemas: make(map[string]*SchemaDB),
	}, nil
}

// CreateSchema creates a new PostgreSQL schema for an app.
func (db *AppAwareDB) CreateSchema(ctx context.Context, schemaName string) error {
	// Validate schema name to prevent SQL injection
	if !isValidSchemaName(schemaName) {
		return fmt.Errorf("invalid schema name: %s", schemaName)
	}

	// Create schema if it doesn't exist
	query := fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schemaName)
	_, err := db.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	return nil
}

// DropSchema drops a PostgreSQL schema and all its contents.
// Use with caution - this deletes all data in the schema.
func (db *AppAwareDB) DropSchema(ctx context.Context, schemaName string) error {
	if !isValidSchemaName(schemaName) {
		return fmt.Errorf("invalid schema name: %s", schemaName)
	}

	query := fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schemaName)
	_, err := db.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to drop schema: %w", err)
	}

	// Remove from cache
	db.mu.Lock()
	delete(db.schemas, schemaName)
	db.mu.Unlock()

	return nil
}

// ListSchemas returns all app schemas in the database.
func (db *AppAwareDB) ListSchemas(ctx context.Context) ([]string, error) {
	query := `
		SELECT schema_name
		FROM information_schema.schemata
		WHERE schema_name LIKE 'app_%'
		ORDER BY schema_name
	`
	rows, err := db.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list schemas: %w", err)
	}
	defer rows.Close()

	var schemas []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("failed to scan schema name: %w", err)
		}
		schemas = append(schemas, name)
	}

	return schemas, rows.Err()
}

// GetSchemaSize returns the size of a schema in bytes.
func (db *AppAwareDB) GetSchemaSize(ctx context.Context, schemaName string) (int64, error) {
	if !isValidSchemaName(schemaName) {
		return 0, fmt.Errorf("invalid schema name: %s", schemaName)
	}

	query := `
		SELECT COALESCE(SUM(pg_total_relation_size(quote_ident(schemaname) || '.' || quote_ident(tablename))), 0)
		FROM pg_tables
		WHERE schemaname = $1
	`
	var size int64
	err := db.pool.QueryRow(ctx, query, schemaName).Scan(&size)
	if err != nil {
		return 0, fmt.Errorf("failed to get schema size: %w", err)
	}

	return size, nil
}

// ForSchema returns a SchemaDB scoped to a specific schema. The name is
// used in SQL, so it must be a plain identifier (lowercase letters, digits,
// and underscores); anything else is refused.
func (db *AppAwareDB) ForSchema(schemaName string) (*SchemaDB, error) {
	if !isValidSchemaName(schemaName) {
		return nil, fmt.Errorf("multiapp: invalid schema name %q", schemaName)
	}

	db.mu.RLock()
	if schemaDB, ok := db.schemas[schemaName]; ok {
		db.mu.RUnlock()
		return schemaDB, nil
	}
	db.mu.RUnlock()

	db.mu.Lock()
	defer db.mu.Unlock()

	// Double-check after acquiring write lock
	if schemaDB, ok := db.schemas[schemaName]; ok {
		return schemaDB, nil
	}

	schemaDB := &SchemaDB{
		pool:   db.pool,
		schema: schemaName,
	}
	db.schemas[schemaName] = schemaDB
	return schemaDB, nil
}

// Pool returns the underlying connection pool.
func (db *AppAwareDB) Pool() *pgxpool.Pool {
	return db.pool
}

// Close closes the database connection pool.
func (db *AppAwareDB) Close() error {
	db.pool.Close()
	return nil
}

// isValidSchemaName validates a schema name to prevent SQL injection.
func isValidSchemaName(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	// Only allow lowercase letters, numbers, and underscores
	for _, c := range name {
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '0' && c <= '9'
		isUnderscore := c == '_'
		if !isLower && !isDigit && !isUnderscore {
			return false
		}
	}
	// Must start with a letter or underscore
	first := name[0]
	return (first >= 'a' && first <= 'z') || first == '_'
}

// SchemaDB provides database operations scoped to a specific schema.
type SchemaDB struct {
	pool   *pgxpool.Pool
	schema string
}

// Schema returns the schema name.
func (db *SchemaDB) Schema() string {
	return db.schema
}

// setSearchPath scopes the schema to the current transaction. SET LOCAL,
// unlike SET, ends with the transaction, so a pooled connection never
// goes back to the pool carrying one application's schema.
func (db *SchemaDB) setSearchPath(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL search_path TO %s, public", db.schema)); err != nil {
		return fmt.Errorf("failed to set search_path: %w", err)
	}
	return nil
}

// Exec executes a statement with the schema's search_path, in its own
// transaction.
func (db *SchemaDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return tag, errors.Join(err, tx.Rollback(ctx))
	}
	return tag, tx.Commit(ctx)
}

// Query executes a query and returns rows with the schema's search_path.
// The rows hold a transaction open until they are closed (Close, or Next
// returning false), so always close them.
func (db *SchemaDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, errors.Join(err, tx.Rollback(ctx))
	}
	return &schemaRows{Rows: rows, tx: tx, ctx: ctx}, nil
}

// QueryRow executes a query and returns a single row with the schema's
// search_path. The transaction ends when the row is scanned.
func (db *SchemaDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return errRow{err}
	}
	return &schemaRow{rows: rows}
}

// schemaRows ends the transaction its rows were read in: committing it
// when the query succeeded, so a write that returns rows (INSERT ...
// RETURNING) takes effect, and rolling it back otherwise.
type schemaRows struct {
	pgx.Rows
	tx     *SchemaTx
	ctx    context.Context
	closed bool
	endErr error
}

func (r *schemaRows) Next() bool {
	if r.Rows.Next() {
		return true
	}
	r.Close()
	return false
}

func (r *schemaRows) Close() {
	if r.closed {
		return
	}
	r.closed = true
	r.Rows.Close()
	if r.Rows.Err() != nil {
		if err := r.tx.Rollback(r.ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			slog.Error("multiapp: rolling back a failed query", "error", err)
		}
		return
	}
	r.endErr = r.tx.Commit(r.ctx)
}

// Err returns the query's error, or the failure to end its transaction.
func (r *schemaRows) Err() error {
	if err := r.Rows.Err(); err != nil {
		return err
	}
	return r.endErr
}

// schemaRow scans a single row and ends its transaction.
type schemaRow struct{ rows pgx.Rows }

func (r *schemaRow) Scan(dest ...any) error {
	defer r.rows.Close()
	if !r.rows.Next() {
		if err := r.rows.Err(); err != nil {
			return err
		}
		return pgx.ErrNoRows
	}
	if err := r.rows.Scan(dest...); err != nil {
		return err
	}
	r.rows.Close()
	return r.rows.Err()
}

// errRow is a row that failed to start.
type errRow struct{ err error }

func (r errRow) Scan(...any) error { return r.err }

// Begin starts a transaction with the schema's search_path.
func (db *SchemaDB) Begin(ctx context.Context) (*SchemaTx, error) {
	return db.BeginTx(ctx, pgx.TxOptions{})
}

// BeginTx starts a transaction with options and the schema's search_path.
func (db *SchemaDB) BeginTx(ctx context.Context, opts pgx.TxOptions) (*SchemaTx, error) {
	tx, err := db.pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if err := db.setSearchPath(ctx, tx); err != nil {
		return nil, errors.Join(err, tx.Rollback(ctx))
	}
	return &SchemaTx{tx: tx, schema: db.schema}, nil
}

// AcquireConn acquires a connection with the schema's search_path set for
// the whole session.
//
// Deprecated: the setting stays on the connection after Release, so the
// pool can hand it, with this schema, to unrelated code. Use Begin, whose
// search_path ends with the transaction.
func (db *SchemaDB) AcquireConn(ctx context.Context) (*pgxpool.Conn, error) {
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}

	// Set search_path for this connection
	_, err = conn.Exec(ctx, fmt.Sprintf("SET search_path TO %s, public", db.schema))
	if err != nil {
		conn.Release()
		return nil, fmt.Errorf("failed to set search_path: %w", err)
	}

	return conn, nil
}

// Pool returns the underlying connection pool.
func (db *SchemaDB) Pool() *pgxpool.Pool {
	return db.pool
}

// StdDB returns a *sql.DB wrapper for use with Ent or other SQL libraries.
// Note: This creates a new connection per call; consider caching if needed.
func (db *SchemaDB) StdDB(ctx context.Context) (*sql.DB, error) {
	// pgx v5 doesn't directly support *sql.DB, so we need to use database/sql
	// with the pgx driver
	return nil, errors.New("StdDB not implemented - use pgx directly or integrate with Ent")
}

// SchemaTx is a transaction scoped to a schema.
type SchemaTx struct {
	tx     pgx.Tx
	schema string
}

// Exec executes a query in the transaction.
func (tx *SchemaTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return tx.tx.Exec(ctx, sql, args...)
}

// Query executes a query and returns rows in the transaction.
func (tx *SchemaTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return tx.tx.Query(ctx, sql, args...)
}

// QueryRow executes a query and returns a single row in the transaction.
func (tx *SchemaTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return tx.tx.QueryRow(ctx, sql, args...)
}

// Commit commits the transaction.
func (tx *SchemaTx) Commit(ctx context.Context) error {
	return tx.tx.Commit(ctx)
}

// Rollback rolls back the transaction.
func (tx *SchemaTx) Rollback(ctx context.Context) error {
	return tx.tx.Rollback(ctx)
}
