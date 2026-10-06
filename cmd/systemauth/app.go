package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
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

// loadConfig builds the configuration from the config file (if any) and
// the flag/environment overrides.
func loadConfig(opts *options) (*systemauth.Config, error) {
	var cfg *systemauth.Config
	if opts.configFile != "" {
		c, err := systemauth.LoadConfig(opts.configFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
		cfg = c
	} else {
		cfg = &systemauth.Config{}
	}

	if opts.issuer != "" {
		cfg.Issuer = opts.issuer
	}
	if cfg.Issuer == "" && opts.dev {
		host := opts.addr
		if strings.HasPrefix(host, ":") {
			host = "localhost" + host
		}
		cfg.Issuer = "http://" + host
	}
	if opts.dbDriver != "" || opts.dbDSN != "" {
		if opts.dbDriver == "" || opts.dbDSN == "" {
			return nil, errors.New("--db-driver and --db-dsn must be set together")
		}
		cfg.Database = &systemauth.DatabaseConfig{Driver: opts.dbDriver, DSN: os.ExpandEnv(opts.dbDSN)}
	}
	if opts.signingKeyFile != "" {
		cfg.Keys.PrivateKeyFile = opts.signingKeyFile
		cfg.Keys.PrivateKeyPEM = ""
	}
	if pem := os.Getenv(signingKeyEnv); pem != "" && !cfg.Keys.HasSigningKey() {
		cfg.Keys.PrivateKeyPEM = pem
	}
	if opts.keyID != "" {
		cfg.Keys.KeyID = opts.keyID
	}

	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	return cfg, nil
}

// checkProduction enforces the deployment requirements that --dev relaxes.
func checkProduction(cfg *systemauth.Config, dev bool) error {
	if dev {
		return nil
	}
	var problems []string
	if !cfg.Keys.HasSigningKey() {
		problems = append(problems, "a signing key is required (keys.private_key_file, keys.private_key_pem, --signing-key-file or "+signingKeyEnv+")")
	}
	if u, err := url.Parse(cfg.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
		problems = append(problems, "the issuer must be a public https URL")
	}
	if cfg.Database == nil {
		problems = append(problems, "a persistent database is required (database or --db-driver/--db-dsn)")
	}
	if cfg.SocialLogin != nil && cfg.SocialLogin.InsecureCookies {
		problems = append(problems, "social_login.insecure_cookies is not allowed")
	}
	if len(problems) > 0 {
		return fmt.Errorf("refusing to start outside --dev: %s", strings.Join(problems, "; "))
	}
	return nil
}

// database is an open Ent client with its underlying connection pool.
type database struct {
	client *ent.Client
	db     *sql.DB
}

func (d *database) close(logger *slog.Logger) {
	if err := d.client.Close(); err != nil {
		logger.Error("closing database", "error", err)
	}
}

// openDatabase opens the configured database. PostgreSQL uses the pgx
// stdlib driver with Ent's postgres dialect.
func openDatabase(cfg *systemauth.DatabaseConfig) (*database, error) {
	var driverName, dialectName string
	switch cfg.Driver {
	case "postgres", "postgresql", "pgx":
		driverName, dialectName = "pgx", dialect.Postgres
	case "sqlite", "sqlite3":
		driverName, dialectName = "sqlite3", dialect.SQLite
	case "mysql":
		return nil, errors.New("database driver mysql is not compiled into this binary; use postgres or sqlite")
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Driver)
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
	drv := entsql.OpenDB(dialectName, db)
	return &database{client: ent.NewClient(ent.Driver(drv)), db: db}, nil
}

// app is a fully wired SystemAuth server.
type app struct {
	cfg         *systemauth.Config
	server      *systemauth.Server
	db          *database
	storageName string
}

func (a *app) close(logger *slog.Logger) {
	if a.db != nil {
		a.db.close(logger)
	}
}

// newApp loads configuration, enforces production requirements, connects
// to and migrates the database, and builds the server.
func newApp(ctx context.Context, opts *options, logger *slog.Logger) (*app, error) {
	cfg, err := loadConfig(opts)
	if err != nil {
		return nil, err
	}
	if err := checkProduction(cfg, opts.dev); err != nil {
		return nil, err
	}
	if opts.dev {
		logger.Warn("development mode: production safeguards are disabled")
	}

	a := &app{cfg: cfg, storageName: "in-memory"}
	serverOpts := []systemauth.Option{systemauth.WithLogger(logger)}

	if cfg.Database != nil {
		logger.Info("connecting to database", "driver", cfg.Database.Driver)
		db, err := openDatabase(cfg.Database)
		if err != nil {
			return nil, err
		}
		a.db = db
		pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = db.db.PingContext(pingCtx)
		cancel()
		if err != nil {
			a.close(logger)
			return nil, fmt.Errorf("connecting to database: %w", err)
		}
		if opts.migrate {
			logger.Info("running database migrations")
			if err := db.client.Schema.Create(ctx); err != nil {
				a.close(logger)
				return nil, fmt.Errorf("running migrations: %w", err)
			}
		}
		ownerID, err := ensureSystemUser(ctx, db.client, logger)
		if err != nil {
			a.close(logger)
			return nil, fmt.Errorf("creating system user: %w", err)
		}
		serverOpts = append(serverOpts,
			systemauth.WithStorage(systemauth.NewEntStorage(db.client, systemauth.WithDefaultOwner(ownerID))),
			systemauth.WithReadinessCheck("database", db.db.PingContext),
		)
		a.storageName = cfg.Database.Driver
	} else {
		logger.Warn("using in-memory storage (data will not persist)")
	}

	server, err := systemauth.NewEmbedded(*cfg, serverOpts...)
	if err != nil {
		a.close(logger)
		return nil, fmt.Errorf("creating server: %w", err)
	}
	a.server = server
	return a, nil
}

// ensureSystemUser creates or retrieves the system user that owns
// statically configured OAuth clients.
func ensureSystemUser(ctx context.Context, client *ent.Client, logger *slog.Logger) (uuid.UUID, error) {
	const systemEmail = "system@systemauth.local"
	systemID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	existing, err := client.User.Get(ctx, systemID)
	if err == nil {
		return existing.ID, nil
	}
	if !ent.IsNotFound(err) {
		return uuid.Nil, err
	}
	existing, err = client.User.Query().Where(user.EmailEQ(systemEmail)).First(ctx)
	if err == nil {
		return existing.ID, nil
	}
	if !ent.IsNotFound(err) {
		return uuid.Nil, err
	}

	logger.Info("creating system user for standalone mode")
	created, err := client.User.Create().
		SetID(systemID).
		SetEmail(systemEmail).
		SetName("SystemAuth System").
		SetIsPlatformAdmin(true).
		SetActive(true).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			// Another instance created it concurrently.
			existing, getErr := client.User.Get(ctx, systemID)
			if getErr == nil {
				return existing.ID, nil
			}
		}
		return uuid.Nil, err
	}
	return created.ID, nil
}
