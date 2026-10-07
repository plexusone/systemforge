package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// loadConfig builds the configuration from the config file (if any) and
// the flag/environment overrides.
func loadConfig(opts *options) (*systemauthsvc.Config, error) {
	if (opts.dbDriver == "") != (opts.dbDSN == "") {
		return nil, errors.New("--db-driver and --db-dsn must be set together")
	}
	overrides := []systemauthsvc.Override{
		systemauthsvc.WithIssuer(opts.issuer),
		systemauthsvc.WithDatabase(opts.dbDriver, opts.dbDSN),
		systemauthsvc.WithSigningKeyFile(opts.signingKeyFile),
		systemauthsvc.WithDefaultSigningKeyPEM(os.Getenv(signingKeyEnv)),
		systemauthsvc.WithKeyID(opts.keyID),
	}
	if opts.dev {
		host := opts.addr
		if strings.HasPrefix(host, ":") {
			host = "localhost" + host
		}
		overrides = append(overrides, systemauthsvc.WithDefaultIssuer("http://"+host))
	}
	return systemauthsvc.LoadConfig(opts.configFile, overrides...)
}

// serviceOptions maps the command-line options to service options.
func serviceOptions(opts *options, logger *slog.Logger) systemauthsvc.Options {
	return systemauthsvc.Options{Dev: opts.dev, Logger: logger, Migrate: opts.migrate}
}

// checkProduction enforces the deployment requirements that --dev relaxes,
// naming the command-line ways to supply a signing key.
func checkProduction(cfg *systemauthsvc.Config, opts *options) error {
	return withFlagHint(systemauthsvc.CheckProduction(cfg, systemauthsvc.Options{Dev: opts.dev}))
}

func withFlagHint(err error) error {
	if errors.Is(err, systemauthsvc.ErrNotProductionReady) {
		return fmt.Errorf("%w (outside --dev; a signing key can also be given with --signing-key-file or %s, a database with --db-driver/--db-dsn)", err, signingKeyEnv)
	}
	return err
}

// newApp loads configuration, enforces production requirements, connects
// to and migrates the database, and builds the server.
func newApp(ctx context.Context, opts *options, logger *slog.Logger) (*systemauthsvc.Service, error) {
	cfg, err := loadConfig(opts)
	if err != nil {
		return nil, err
	}
	svc, err := systemauthsvc.New(ctx, cfg, serviceOptions(opts, logger))
	if err != nil {
		return nil, withFlagHint(err)
	}
	return svc, nil
}
