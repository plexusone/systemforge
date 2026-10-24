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

// AppAwareDB is a connection pool for one database login, serving app
// schemas over it.
//
// A pool connected with an app's own login serves that app's schema only:
// ForSchema, the Ent helpers and EntConnHook refuse a second schema, since
// switching schemas inside one login (search_path, or SET LOCAL ROLE,
// which SQL in the transaction can reset) does not keep apps apart. Open
// the pool of the migration (owner) login with AsMigrationLogin, and a
// pool every app shares, for local development only, with
// AllowSharedLogin. See "Database isolation" in the package README.
type AppAwareDB struct {
	pool    *pgxpool.Pool
	schemas map[string]*SchemaDB
	mu      sync.RWMutex
	opts    dbOptions
	// bound is the one schema a single-app pool serves.
	bound string
}

// DBOption configures an AppAwareDB.
type DBOption func(*dbOptions)

type dbOptions struct {
	multiSchema bool
}

// AsMigrationLogin marks the pool as the migration (owner) login, which
// creates every app schema and runs migrations in them, so it may serve
// any number of schemas. Never hand it to app code.
func AsMigrationLogin() DBOption {
	return func(o *dbOptions) { o.multiSchema = true }
}

// AllowSharedLogin lets app code use one pool, and so one database login,
// for several app schemas. The database then does not keep the apps
// apart: any of them can read and write the others' tables with a
// schema-qualified name. Use it for local development only.
func AllowSharedLogin() DBOption {
	return func(o *dbOptions) { o.multiSchema = true }
}

// ErrSharedDatabaseLogin is returned when a pool connected with one app's
// login is asked to serve another app's schema.
var ErrSharedDatabaseLogin = errors.New("multiapp: one database login cannot serve several app schemas")

// NewAppAwareDB opens a connection pool for databaseURL and checks that it
// connects.
func NewAppAwareDB(databaseURL string, opts ...DBOption) (*AppAwareDB, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}
	return NewAppAwareDBWithConfig(context.Background(), config, opts...)
}

// NewAppAwareDBWithConfig opens a connection pool from config, for example
// one whose BeforeConnect sets a short-lived IAM authentication token as
// the password, and checks that it connects.
func NewAppAwareDBWithConfig(ctx context.Context, config *pgxpool.Config, opts ...DBOption) (*AppAwareDB, error) {
	if config == nil {
		return nil, errors.New("multiapp: nil pool config")
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	db := &AppAwareDB{
		pool:    pool,
		schemas: make(map[string]*SchemaDB),
	}
	for _, o := range opts {
		o(&db.opts)
	}
	return db, nil
}

// claim validates schema and records it as the schema this pool serves,
// refusing a second one unless the pool may serve several.
func (db *AppAwareDB) claim(schema string) error {
	if !isValidSchemaName(schema) {
		return fmt.Errorf("multiapp: invalid schema name %q", schema)
	}
	if db == nil {
		return errors.New("multiapp: no database")
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.opts.multiSchema {
		return nil
	}
	if db.bound == "" {
		db.bound = schema
		return nil
	}
	if db.bound != schema {
		return fmt.Errorf("%w: this pool serves schema %q, not %q; give each app its own login (or use AllowSharedLogin for local development)",
			ErrSharedDatabaseLogin, db.bound, schema)
	}
	return nil
}

// CreateSchema creates a new PostgreSQL schema for an app.
func (db *AppAwareDB) CreateSchema(ctx context.Context, schemaName string) error {
	// Validate schema name to prevent SQL injection
	if !isValidSchemaName(schemaName) {
		return fmt.Errorf("invalid schema name: %s", schemaName)
	}

	// A provisioned schema already exists, and the migration login that
	// owns it need not hold CREATE on the database, which CREATE SCHEMA IF
	// NOT EXISTS checks even when the schema exists.
	var exists bool
	if err := db.pool.QueryRow(ctx, "SELECT EXISTS (SELECT FROM pg_catalog.pg_namespace WHERE nspname = $1)", schemaName).Scan(&exists); err != nil {
		return fmt.Errorf("failed to look up schema: %w", err)
	}
	if exists {
		return nil
	}
	query := fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", quoteIdent(schemaName))
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
// and underscores); anything else is refused. Unless the pool was opened
// with AsMigrationLogin or AllowSharedLogin, it serves one schema only, and
// asking for a second returns ErrSharedDatabaseLogin.
func (db *AppAwareDB) ForSchema(schemaName string) (*SchemaDB, error) {
	if err := db.claim(schemaName); err != nil {
		return nil, err
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

// StdDB opens a *sql.DB for use with Ent or other database/sql libraries,
// connected with the same login as this SchemaDB and with search_path set
// to its schema on every connection. Each call opens a new pool; open it
// once per app and close it when done. Usage with Ent:
//
//	db, err := deps.DB.StdDB(ctx)
//	if err != nil {
//	    return err
//	}
//	client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
func (db *SchemaDB) StdDB(ctx context.Context) (*sql.DB, error) {
	return openStdDB(ctx, db.pool.Config().ConnConfig, db.schema)
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
