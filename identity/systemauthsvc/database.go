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
	"github.com/plexusone/connectionforge/sqlstore"

	"github.com/plexusone/systemforge/connections"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/pgschema"
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
	// Dialect is the Ent dialect (dialect.Postgres or dialect.SQLite).
	Dialect string
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
	return &Database{Client: ent.NewClient(ent.Driver(entsql.OpenDB(dialectName, db))), DB: db, Dialect: dialectName}
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
	if err := migrate(ctx, db.Client, db.Dialect); err != nil {
		return err
	}
	if cfg.Connections != nil {
		return connections.MigrateSchema(ctx, db.DB, sqlstore.Dialect(db.Dialect), nil)
	}
	return nil
}

// migrate creates or updates the Ent schema and, on PostgreSQL, the
// schema objects Ent cannot express (see pgschema).
func migrate(ctx context.Context, client *ent.Client, dialectName string) error {
	if err := client.Schema.Create(ctx); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	if dialectName == dialect.Postgres {
		if err := pgschema.Apply(ctx, client); err != nil {
			return fmt.Errorf("running PostgreSQL migrations: %w", err)
		}
	}
	return nil
}

// System service principal that owns statically configured OAuth clients.
const (
	systemPrincipalIdentifier  = "system@systemauth.local"
	systemPrincipalName        = "SystemAuth System"
	systemPrincipalServiceType = "systemauth"
)

// systemPrincipalID is fixed so every instance resolves the same owner and
// owner_id values written by earlier versions remain valid.
var systemPrincipalID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// ensureSystemPrincipal creates or retrieves the service principal that owns
// statically configured OAuth clients. It reports whether it created one.
func ensureSystemPrincipal(ctx context.Context, client *ent.Client) (uuid.UUID, bool, error) {
	id, found, err := findSystemPrincipal(ctx, client)
	if err != nil || found {
		return id, false, err
	}
	if err := createSystemPrincipal(ctx, client); err != nil {
		if ent.IsConstraintError(err) {
			// Another instance created it concurrently.
			id, found, getErr := findSystemPrincipal(ctx, client)
			if getErr == nil && found {
				return id, false, nil
			}
		}
		return uuid.Nil, false, err
	}
	return systemPrincipalID, true, nil
}

// findSystemPrincipal looks the system principal up by its fixed ID, then by
// its identifier.
func findSystemPrincipal(ctx context.Context, client *ent.Client) (uuid.UUID, bool, error) {
	existing, err := client.Principal.Get(ctx, systemPrincipalID)
	if err == nil {
		return existing.ID, true, nil
	}
	if !ent.IsNotFound(err) {
		return uuid.Nil, false, err
	}
	existing, err = client.Principal.Query().
		Where(principal.IdentifierEQ(systemPrincipalIdentifier)).
		First(ctx)
	if err == nil {
		return existing.ID, true, nil
	}
	if !ent.IsNotFound(err) {
		return uuid.Nil, false, err
	}
	return uuid.Nil, false, nil
}

// createSystemPrincipal inserts the principal and its service extension in
// one transaction.
func createSystemPrincipal(ctx context.Context, client *ent.Client) (err error) {
	tx, err := client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rerr := tx.Rollback(); rerr != nil {
				err = errors.Join(err, fmt.Errorf("rolling back: %w", rerr))
			}
		}
	}()

	if _, err = tx.Principal.Create().
		SetID(systemPrincipalID).
		SetType(principal.TypeService).
		SetIdentifier(systemPrincipalIdentifier).
		SetDisplayName(systemPrincipalName).
		SetActive(true).
		Save(ctx); err != nil {
		return err
	}
	if _, err = tx.ServicePrincipal.Create().
		SetPrincipalID(systemPrincipalID).
		SetServiceType(systemPrincipalServiceType).
		SetDescription("Owns OAuth clients defined in SystemAuth configuration").
		Save(ctx); err != nil {
		return err
	}
	return tx.Commit()
}
