package systemauthsvc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/user"
	"github.com/plexusone/systemforge/identity/systemauth"

	// Database drivers: "pgx" (PostgreSQL) and "sqlite3".
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
)

// Database is an Ent client with its underlying connection pool.
type Database struct {
	// Client is the Ent client.
	Client *ent.Client
	// DB is the connection pool.
	DB *sql.DB
}

// Close closes the Ent client and its connection pool.
func (d *Database) Close() error {
	return d.Client.Close()
}

// driverDialect maps a configured driver name to its database/sql driver
// and Ent dialect.
func driverDialect(driver string) (driverName, dialectName string, err error) {
	switch driver {
	case "postgres", "postgresql", "pgx":
		return "pgx", dialect.Postgres, nil
	case "sqlite", "sqlite3":
		return "sqlite3", dialect.SQLite, nil
	case "mysql":
		return "", "", errors.New("database driver mysql is not supported; use postgres or sqlite")
	default:
		return "", "", fmt.Errorf("unsupported database driver: %s", driver)
	}
}

// OpenDatabase opens the configured database without connecting:
// PostgreSQL through the pgx stdlib driver, SQLite through go-sqlite3,
// each with the matching Ent dialect.
func OpenDatabase(cfg *systemauth.DatabaseConfig) (*Database, error) {
	driverName, dialectName, err := driverDialect(cfg.Driver)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driverName, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("opening %s database: %w", cfg.Driver, err)
	}
	if dialectName == dialect.Postgres {
		db.SetMaxOpenConns(20)
		db.SetMaxIdleConns(5)
		db.SetConnMaxIdleTime(5 * time.Minute)
	}
	return wrapDB(db, dialectName), nil
}

func wrapDB(db *sql.DB, dialectName string) *Database {
	return &Database{Client: ent.NewClient(ent.Driver(entsql.OpenDB(dialectName, db))), DB: db}
}

// Migrate opens the configured database, creates or updates the schema,
// and closes it. Migrations are idempotent.
func Migrate(ctx context.Context, cfg *Config) (err error) {
	if cfg.Database == nil {
		return errors.New("database configuration required for migrations")
	}
	db, err := OpenDatabase(cfg.Database)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := db.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing database: %w", cerr)
		}
	}()
	return migrate(ctx, db.Client)
}

func migrate(ctx context.Context, client *ent.Client) error {
	if err := client.Schema.Create(ctx); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}

// System user that owns statically configured OAuth clients.
const systemUserEmail = "system@systemauth.local"

var systemUserID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// ensureSystemUser creates or retrieves the system user that owns
// statically configured OAuth clients.
func ensureSystemUser(ctx context.Context, client *ent.Client) (uuid.UUID, bool, error) {
	existing, err := client.User.Get(ctx, systemUserID)
	if err == nil {
		return existing.ID, false, nil
	}
	if !ent.IsNotFound(err) {
		return uuid.Nil, false, err
	}
	existing, err = client.User.Query().Where(user.EmailEQ(systemUserEmail)).First(ctx)
	if err == nil {
		return existing.ID, false, nil
	}
	if !ent.IsNotFound(err) {
		return uuid.Nil, false, err
	}

	created, err := client.User.Create().
		SetID(systemUserID).
		SetEmail(systemUserEmail).
		SetName("SystemAuth System").
		SetIsPlatformAdmin(true).
		SetActive(true).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			// Another instance created it concurrently.
			existing, getErr := client.User.Get(ctx, systemUserID)
			if getErr == nil {
				return existing.ID, false, nil
			}
		}
		return uuid.Nil, false, err
	}
	return created.ID, true, nil
}
