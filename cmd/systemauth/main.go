// Package main provides a standalone SystemAuth OAuth 2.0 / OpenID Connect server.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/user"
	"github.com/plexusone/systemforge/identity/systemauth"

	// Database drivers
	_ "github.com/mattn/go-sqlite3"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "systemauth",
	Short: "SystemAuth OAuth 2.0 / OpenID Connect server",
	Long: `SystemAuth is a standalone OAuth 2.0 / OpenID Connect server.

It can be used as:
  - A development OAuth server for testing applications
  - A production OAuth provider for your organization
  - An embedded component in larger applications`,
	Version: version,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the OAuth server",
	Long: `Start the SystemAuth OAuth 2.0 server.

The server will listen on the configured address and serve the following endpoints:
  - GET  /.well-known/openid-configuration  OpenID Connect discovery
  - GET  /.well-known/jwks.json             JSON Web Key Set
  - GET  /oauth/authorize                   Authorization endpoint
  - POST /oauth/token                       Token endpoint
  - POST /oauth/introspect                  Token introspection
  - POST /oauth/revoke                      Token revocation`,
	RunE: runServe,
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	Long: `Run database schema migrations.

This will create or update all required database tables for the OAuth server.
Make sure your database configuration is correct before running this command.`,
	RunE: runMigrate,
}

var (
	configFile string
	listenAddr string
	logLevel   string
	logFormat  string
	dbDriver   string
	dbDSN      string
)

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(migrateCmd)

	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Configuration file (YAML or JSON)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "text", "Log format (text, json)")

	// Database flags (override config file)
	rootCmd.PersistentFlags().StringVar(&dbDriver, "db-driver", "", "Database driver (sqlite, postgres)")
	rootCmd.PersistentFlags().StringVar(&dbDSN, "db-dsn", "", "Database connection string")

	// Serve flags
	serveCmd.Flags().StringVarP(&listenAddr, "listen", "l", ":8080", "Address to listen on")
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("systemauth version %s\n", version)
		fmt.Printf("  commit:  %s\n", commit)
		fmt.Printf("  built:   %s\n", buildDate)
	},
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration file",
	RunE: func(_ *cobra.Command, _ []string) error {
		if configFile == "" {
			return fmt.Errorf("configuration file required (use --config)")
		}

		cfg, err := systemauth.LoadConfig(configFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}

		fmt.Printf("Configuration is valid\n")
		fmt.Printf("  Issuer:  %s\n", cfg.Issuer)
		fmt.Printf("  Clients: %d\n", len(cfg.Clients))
		if cfg.Database != nil {
			fmt.Printf("  Database: %s\n", cfg.Database.Driver)
		} else {
			fmt.Printf("  Database: in-memory\n")
		}
		return nil
	},
}

func runServe(_ *cobra.Command, _ []string) error {
	// Set up logger
	logger := setupLogger()

	// Load configuration
	var cfg systemauth.Config
	if configFile != "" {
		cfgPtr, err := systemauth.LoadConfig(configFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		cfg = *cfgPtr
	} else {
		// Use defaults for development
		cfg = systemauth.Config{
			Issuer: fmt.Sprintf("http://localhost%s", listenAddr),
		}
		logger.Warn("no configuration file specified, using development defaults")
	}

	// Override database config from flags if provided
	if dbDriver != "" && dbDSN != "" {
		cfg.Database = &systemauth.DatabaseConfig{
			Driver: dbDriver,
			DSN:    os.ExpandEnv(dbDSN),
		}
	}

	// Validate configuration
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Set up storage
	var storage systemauth.Storage
	var entClient *ent.Client

	if cfg.Database != nil {
		logger.Info("connecting to database", "driver", cfg.Database.Driver)

		var err error
		entClient, err = openDatabase(cfg.Database)
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer func() { _ = entClient.Close() }()

		// Run auto-migration
		logger.Info("running database migrations")
		if err := entClient.Schema.Create(context.Background()); err != nil {
			return fmt.Errorf("failed to run migrations: %w", err)
		}

		// Create or get system user for standalone mode
		systemOwnerID, err := ensureSystemUser(context.Background(), entClient, logger)
		if err != nil {
			return fmt.Errorf("failed to create system user: %w", err)
		}

		storage = systemauth.NewEntStorage(entClient, systemauth.WithDefaultOwner(systemOwnerID))
		logger.Info("using database storage", "driver", cfg.Database.Driver)
	} else {
		storage = systemauth.NewMemoryStorage()
		logger.Info("using in-memory storage (data will not persist)")
	}

	// Create server with storage
	server, err := systemauth.NewEmbedded(cfg,
		systemauth.WithLogger(logger),
		systemauth.WithStorage(storage),
	)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         listenAddr,
		Handler:      server,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		storageType := "in-memory"
		if cfg.Database != nil {
			storageType = cfg.Database.Driver
		}
		logger.Info("starting SystemAuth server",
			"listen", listenAddr,
			"issuer", cfg.Issuer,
			"clients", len(cfg.Clients),
			"storage", storageType,
		)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	case sig := <-quit:
		logger.Info("shutting down server", "signal", sig)
	}

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}

	logger.Info("server stopped")
	return nil
}

func runMigrate(_ *cobra.Command, _ []string) error {
	logger := setupLogger()

	// Load configuration
	var cfg *systemauth.Config
	if configFile != "" {
		var err error
		cfg, err = systemauth.LoadConfig(configFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	} else {
		cfg = &systemauth.Config{}
	}

	// Override database config from flags if provided
	if dbDriver != "" && dbDSN != "" {
		cfg.Database = &systemauth.DatabaseConfig{
			Driver: dbDriver,
			DSN:    os.ExpandEnv(dbDSN),
		}
	}

	if cfg.Database == nil {
		return fmt.Errorf("database configuration required for migrations")
	}

	logger.Info("connecting to database", "driver", cfg.Database.Driver)
	entClient, err := openDatabase(cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() { _ = entClient.Close() }()

	logger.Info("running database migrations")
	if err := entClient.Schema.Create(context.Background()); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	logger.Info("migrations completed successfully")
	return nil
}

// ensureSystemUser creates or retrieves the system user for standalone mode.
// This user owns all statically configured OAuth clients.
func ensureSystemUser(ctx context.Context, client *ent.Client, logger *slog.Logger) (uuid.UUID, error) {
	systemEmail := "system@systemauth.local"
	systemID := uuid.MustParse("00000000-0000-0000-0000-000000000001")

	// Try to get existing user by ID first
	existingUser, err := client.User.Get(ctx, systemID)
	if err == nil {
		return existingUser.ID, nil
	}

	// Try to find by email
	existingUser, err = client.User.Query().
		Where(user.EmailEQ(systemEmail)).
		First(ctx)
	if err == nil {
		return existingUser.ID, nil
	}

	// Create system user
	logger.Info("creating system user for standalone mode")
	newUser, err := client.User.Create().
		SetID(systemID).
		SetEmail(systemEmail).
		SetName("SystemAuth System").
		SetIsPlatformAdmin(true).
		SetActive(true).
		Save(ctx)
	if err != nil {
		// If it failed due to duplicate, try to get existing again
		if ent.IsConstraintError(err) {
			existingUser, getErr := client.User.Get(ctx, systemID)
			if getErr == nil {
				return existingUser.ID, nil
			}
		}
		return uuid.Nil, err
	}

	return newUser.ID, nil
}

func openDatabase(cfg *systemauth.DatabaseConfig) (*ent.Client, error) {
	switch cfg.Driver {
	case "sqlite":
		return ent.Open("sqlite3", cfg.DSN)
	case "postgres":
		return ent.Open("postgres", cfg.DSN)
	case "mysql":
		return ent.Open("mysql", cfg.DSN)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Driver)
	}
}

func setupLogger() *slog.Logger {
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	if logFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
