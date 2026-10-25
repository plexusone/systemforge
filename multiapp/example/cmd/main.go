// Package main demonstrates running apps in single-app and multi-app modes.
//
// The app connects with its own database login, and its schema and
// migrations run with a separate migration (owner) login, in a step of
// their own. Provision both logins once with an admin login (see
// "Database isolation" in the multiapp README), for example:
//
//	go run ./cmd/multiappdb apply --admin-url-env ADMIN_DATABASE_URL \
//	    --owner sf_owner --app example --role app_example_login \
//	    --password-env EXAMPLE_DB_PASSWORD
//
// Migrate, with the owner login, as a separate step (in production a
// one-off task given only the owner's secret):
//
//	MIGRATION_DATABASE_URL=postgres://sf_owner@... go run main.go migrate
//
// Then serve, with the app's own login only. Single-app mode (dedicated
// deployment):
//
//	MODE=single MIGRATION_ROLE=sf_owner \
//	    EXAMPLE_DATABASE_URL=postgres://app_example_login@... go run main.go
//
// Multi-app mode (shared deployment): the same, with MODE=multi.
//
// For local development only, the server can run the migrations itself
// with the owner login:
//
//	IN_PROCESS_MIGRATIONS=1 MIGRATION_DATABASE_URL=postgres://sf_owner@... \
//	    EXAMPLE_DATABASE_URL=postgres://app_example_login@... go run main.go
//
// or every app can share the owner login, which the database then does not
// keep apart:
//
//	SHARED_DATABASE_LOGIN=1 MIGRATION_DATABASE_URL=postgres://... go run main.go
//
// Then test with:
//
//	# Single-app mode:
//	curl http://localhost:8080/api/info
//
//	# Multi-app mode:
//	curl -H "X-App-ID: example" http://localhost:8080/api/info
package main

import (
	"context"
	"log"
	"log/slog"
	"os"

	"github.com/plexusone/systemforge/multiapp"
	"github.com/plexusone/systemforge/multiapp/example"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		// The migration step: the only process given the owner login.
		if err := multiapp.Migrate(context.Background(), os.Getenv("MIGRATION_DATABASE_URL"), example.NewExampleApp()); err != nil {
			log.Fatalf("Migration failed: %v", err)
		}
		log.Print("migrations applied")
		return
	}

	// Get configuration from environment
	mode := os.Getenv("MODE")
	if mode == "" {
		mode = "single"
	}

	// The example app's own login. The server holds the migration (owner)
	// login only in local development (IN_PROCESS_MIGRATIONS or
	// SHARED_DATABASE_LOGIN); otherwise "migrate" runs the migrations
	// beforehand and MIGRATION_ROLE names the owner for the isolation
	// check.
	appDatabases := map[string]multiapp.AppDatabase{}
	if u := os.Getenv("EXAMPLE_DATABASE_URL"); u != "" {
		appDatabases["example"] = multiapp.AppDatabase{URL: u}
	}
	sharedLogin := os.Getenv("SHARED_DATABASE_LOGIN") == "1"
	inProcessMigrations := os.Getenv("IN_PROCESS_MIGRATIONS") == "1"
	var migrationURL string
	if sharedLogin || inProcessMigrations {
		migrationURL = os.Getenv("MIGRATION_DATABASE_URL")
	}

	redisURL := os.Getenv("REDIS_URL") // Optional

	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}

	// Create logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Determine server mode
	var serverMode multiapp.ServerMode
	switch mode {
	case "multi":
		serverMode = multiapp.MultiAppMode
	default:
		serverMode = multiapp.SingleAppMode
	}

	// Create server
	server, err := multiapp.NewServer(multiapp.Config{
		Mode:                     serverMode,
		AppDatabases:             appDatabases,
		MigrationDatabaseURL:     migrationURL,
		AllowInProcessMigrations: inProcessMigrations,
		MigrationRole:            os.Getenv("MIGRATION_ROLE"),
		AllowSharedDatabaseLogin: sharedLogin,
		RedisURL:                 redisURL,
		Logger:                   logger,
	})
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Register apps
	// In multi-app mode, you'd register multiple apps here
	// In single-app mode, you typically register just one

	exampleApp := example.NewExampleApp()
	if err := server.RegisterApp(exampleApp); err != nil {
		log.Fatalf("Failed to register example app: %v", err)
	}

	// In multi-app mode, you might register more apps:
	// if serverMode == multiapp.MultiAppMode {
	//     server.RegisterApp(app1.NewApp())
	//     server.RegisterApp(app2.NewApp())
	//     server.RegisterApp(app3.NewApp())
	// }

	logger.Info("starting server",
		"mode", serverMode,
		"addr", addr,
		"apps", server.Apps(),
	)

	// Run server (blocks until shutdown)
	if err := server.Run(addr); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
