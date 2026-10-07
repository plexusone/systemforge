package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// options holds the command-line configuration. Every flag can also be set
// through an environment variable (see envVars), so a service manager can
// pass configuration via an environment file.
type options struct {
	configFile     string
	addr           string
	issuer         string
	dev            bool
	signingKeyFile string
	keyID          string
	dbDriver       string
	dbDSN          string
	logLevel       string
	logFormat      string
	migrate        bool
}

// envVars maps flag names to the environment variables that set them when
// the flag is not given on the command line.
var envVars = map[string]string{
	"config":           "SYSTEMAUTH_CONFIG",
	"addr":             "SYSTEMAUTH_ADDR",
	"issuer":           "SYSTEMAUTH_ISSUER",
	"dev":              "SYSTEMAUTH_DEV",
	"signing-key-file": "SYSTEMAUTH_SIGNING_KEY_FILE",
	"key-id":           "SYSTEMAUTH_KEY_ID",
	"db-driver":        "SYSTEMAUTH_DB_DRIVER",
	"db-dsn":           "SYSTEMAUTH_DB_DSN",
	"log-level":        "SYSTEMAUTH_LOG_LEVEL",
	"log-format":       "SYSTEMAUTH_LOG_FORMAT",
	"migrate":          "SYSTEMAUTH_MIGRATE",
}

// signingKeyEnv carries a PEM signing key. It is deliberately not a flag:
// command lines are visible to other local users.
const signingKeyEnv = "SYSTEMAUTH_SIGNING_KEY"

const serveLong = `Start the SystemAuth OAuth 2.0 / OpenID Connect server.

Endpoints:
  - GET  /.well-known/openid-configuration  OpenID Connect discovery
  - GET  /.well-known/jwks.json             JSON Web Key Set
  - GET  /oauth/authorize                   Authorization endpoint
  - POST /oauth/token                       Token endpoint
  - POST /oauth/introspect                  Token introspection
  - POST /oauth/revoke                      Token revocation
  - GET  /oauth/userinfo                    OpenID Connect UserInfo
  - GET  /healthz                           Liveness
  - GET  /readyz                            Readiness (database ping)

When social_login is configured, GitHub/Google login is also served:
  - GET  /login                             Provider chooser (return_to=...)
  - GET  /login/{provider}                  Start upstream login
  - GET  /login/{provider}/callback         Upstream callback; sets __Host-sf_login
  - GET  /logout, POST /logout              Sign out; revokes the principal's tokens
  - GET  /consent, POST /consent            Consent page (when skip_consent is false)

Unless --dev is set, the server refuses to start without a persistent
database, an https issuer, and a signing key (keys.private_key_file,
keys.private_key_pem, --signing-key-file or SYSTEMAUTH_SIGNING_KEY).

Every flag can also be set with an environment variable, e.g. --addr with
SYSTEMAUTH_ADDR; single-dash long flags (-addr) are accepted.`

func newRootCmd() *cobra.Command {
	return newRootCmdWithOptions(&options{})
}

// newRootCmdWithOptions builds the command tree, parsing flags into opts.
func newRootCmdWithOptions(opts *options) *cobra.Command {
	root := &cobra.Command{
		Use:   "systemauth",
		Short: "SystemAuth OAuth 2.0 / OpenID Connect server",
		Long: `SystemAuth is a standalone OAuth 2.0 / OpenID Connect server.

Run without a subcommand it serves (same as "systemauth serve").

` + serveLong,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return applyEnv(cmd.Flags())
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), opts)
		},
	}

	pf := root.PersistentFlags()
	pf.StringVarP(&opts.configFile, "config", "c", "", "Configuration file (YAML or JSON)")
	pf.StringVar(&opts.addr, "addr", ":8080", "Address to listen on, e.g. 127.0.0.1:8081")
	pf.StringVar(&opts.issuer, "issuer", "", "Public issuer URL (overrides the config file)")
	pf.BoolVar(&opts.dev, "dev", false, "Development mode: allow an ephemeral signing key, in-memory storage and an http issuer")
	pf.StringVar(&opts.signingKeyFile, "signing-key-file", "", "PEM RSA signing key file (overrides keys.private_key_file)")
	pf.StringVar(&opts.keyID, "key-id", "", "JWKS key ID (overrides keys.key_id; default: key thumbprint)")
	pf.StringVar(&opts.dbDriver, "db-driver", "", "Database driver (postgres, sqlite)")
	pf.StringVar(&opts.dbDSN, "db-dsn", "", "Database connection string")
	pf.StringVar(&opts.logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	pf.StringVar(&opts.logFormat, "log-format", "text", "Log format (text, json)")
	pf.BoolVar(&opts.migrate, "migrate", true, "Run database migrations at startup")
	// --listen is the former name of --addr.
	pf.StringVarP(&opts.addr, "listen", "l", ":8080", "Address to listen on")
	if err := pf.MarkDeprecated("listen", "use --addr"); err != nil {
		panic(err)
	}

	root.AddCommand(
		&cobra.Command{
			Use:   "serve",
			Short: "Start the OAuth server",
			Long:  serveLong,
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runServe(cmd.Context(), opts)
			},
		},
		&cobra.Command{
			Use:   "migrate",
			Short: "Run database migrations",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runMigrate(cmd.Context(), opts)
			},
		},
		&cobra.Command{
			Use:   "validate",
			Short: "Validate the configuration (including production requirements)",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runValidate(cmd, opts)
			},
		},
		&cobra.Command{
			Use:   "version",
			Short: "Print version information",
			Args:  cobra.NoArgs,
			Run: func(cmd *cobra.Command, _ []string) {
				cmd.Printf("systemauth version %s\n  commit:  %s\n  built:   %s\n", version, commit, buildDate)
			},
		},
	)
	return root
}

// normalizeArgs rewrites single-dash long flags ("-addr", "-config=x") to
// the double-dash form cobra expects, so Go-style flag lines work. Single
// letter shorthands ("-c") and everything after "--" are left alone.
func normalizeArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for i, a := range args {
		if a == "--" {
			return append(out, args[i:]...)
		}
		name, _, _ := strings.Cut(strings.TrimPrefix(a, "-"), "=")
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(name) > 1 {
			a = "-" + a
		}
		out = append(out, a)
	}
	return out
}

// applyEnv sets every flag that was not given on the command line from its
// environment variable.
func applyEnv(flags *pflag.FlagSet) error {
	for name, env := range envVars {
		f := flags.Lookup(name)
		if f == nil || f.Changed {
			continue
		}
		v, ok := os.LookupEnv(env)
		if !ok || v == "" {
			continue
		}
		if err := flags.Set(name, v); err != nil {
			return fmt.Errorf("%s: %w", env, err)
		}
	}
	return nil
}

func runValidate(cmd *cobra.Command, opts *options) error {
	cfg, err := loadConfig(opts)
	if err != nil {
		return err
	}
	if err := cfg.Keys.LoadSigningKey(); err != nil {
		return err
	}
	if err := checkProduction(cfg, opts); err != nil {
		return err
	}
	cmd.Printf("Configuration is valid\n  Issuer:   %s\n  Clients:  %d\n", cfg.Issuer, len(cfg.Clients))
	if cfg.Database != nil {
		cmd.Printf("  Database: %s\n", cfg.Database.Driver)
	} else {
		cmd.Printf("  Database: in-memory\n")
	}
	return nil
}

func runServe(ctx context.Context, opts *options) error {
	logger, err := systemauthsvc.NewLogger(os.Stdout, opts.logLevel, opts.logFormat)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	app, err := newApp(ctx, opts, logger)
	if err != nil {
		return err
	}
	defer func() {
		if err := app.Close(); err != nil {
			logger.Error("closing database", "error", err)
		}
	}()

	httpServer := &http.Server{
		Addr:              opts.addr,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errChan := make(chan error, 1)
	go func() {
		logger.Info("starting SystemAuth server",
			"addr", opts.addr,
			"issuer", app.Issuer(),
			"key_id", app.KeyID(),
			"clients", len(app.Config().Clients),
			"storage", app.StorageName(),
			"dev", opts.dev,
			"version", version,
		)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	case sig := <-quit:
		logger.Info("shutting down server", "signal", sig.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown failed: %w", err)
	}
	logger.Info("server stopped")
	return nil
}

func runMigrate(ctx context.Context, opts *options) error {
	logger, err := systemauthsvc.NewLogger(os.Stdout, opts.logLevel, opts.logFormat)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := loadConfig(opts)
	if err != nil {
		return err
	}
	if cfg.Database != nil {
		logger.Info("running database migrations", "driver", cfg.Database.Driver)
	}
	if err := systemauthsvc.Migrate(ctx, cfg); err != nil {
		return err
	}
	logger.Info("migrations completed successfully")
	return nil
}
