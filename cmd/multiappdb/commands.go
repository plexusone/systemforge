package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/multiapp"
)

// roleFlags are the flags describing one app's login.
type roleFlags struct {
	owner         string
	app           string
	schema        string
	role          string
	database      string
	readOnly      bool
	sharedSchema  string
	sharedTables  []string
	defaultShared bool
	noShared      bool
	memberOf      []string
}

func (f *roleFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVar(&f.owner, "owner", "", "migration (owner) role that owns the app schema (required)")
	fl.StringVar(&f.app, "app", "", "app slug; the schema defaults to app_<slug>")
	fl.StringVar(&f.schema, "schema", "", "app schema (default app_<slug>)")
	fl.StringVar(&f.role, "role", "", "the app's login role (required)")
	fl.StringVar(&f.database, "database", "", "database to grant CONNECT on (optional)")
	fl.BoolVar(&f.readOnly, "read-only", false, "grant SELECT only on the app's tables")
	fl.StringVar(&f.sharedSchema, "shared-schema", "public", "schema holding the shared SystemForge tables")
	fl.StringSliceVar(&f.sharedTables, "shared-table", nil, "shared table the app may read, replacing the default list (repeatable; default multiapp.DefaultSharedReadTables)")
	fl.BoolVar(&f.defaultShared, "default-shared-tables", false, "with --shared-table, also grant multiapp.DefaultSharedReadTables")
	fl.BoolVar(&f.noShared, "no-shared-tables", false, "grant no shared table, for an app that does not read the identity tables")
	fl.StringSliceVar(&f.memberOf, "member-of", nil, "role to grant the app role, e.g. rds_iam (repeatable)")
}

func (f *roleFlags) provisioning() (multiapp.RoleProvisioning, error) {
	schema := f.schema
	if schema == "" {
		if f.app == "" {
			return multiapp.RoleProvisioning{}, errors.New("set --app or --schema")
		}
		schema = multiapp.SchemaFromAppSlug(f.app)
	}
	// Nil keeps RoleProvisioning's default, DefaultSharedReadTables.
	var tables []string
	switch {
	case f.noShared:
		if len(f.sharedTables) > 0 || f.defaultShared {
			return multiapp.RoleProvisioning{}, errors.New("--no-shared-tables excludes --shared-table and --default-shared-tables")
		}
		tables = multiapp.NoSharedReadTables
	case len(f.sharedTables) > 0:
		tables = append([]string{}, f.sharedTables...)
		if f.defaultShared {
			tables = append(tables, multiapp.DefaultSharedReadTables...)
		}
	}
	return multiapp.RoleProvisioning{
		Schema:           schema,
		Role:             f.role,
		OwnerRole:        f.owner,
		Database:         f.database,
		ReadOnly:         f.readOnly,
		SharedSchema:     f.sharedSchema,
		SharedReadTables: tables,
		MemberOf:         f.memberOf,
	}, nil
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "multiappdb",
		Short:         "Provision and check per-app database logins for multiapp",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newSQLCmd(), newApplyCmd(), newVerifyCmd())
	return root
}

func newSQLCmd() *cobra.Command {
	var f roleFlags
	var withOwner bool
	cmd := &cobra.Command{
		Use:   "sql",
		Short: "Print the SQL that provisions an app's login (no passwords)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := f.provisioning()
			if err != nil {
				return err
			}
			var stmts []string
			if withOwner {
				owner, err := multiapp.OwnerRoleSQL(f.owner)
				if err != nil {
					return err
				}
				stmts = append(stmts, owner...)
			}
			app, err := p.SQL()
			if err != nil {
				return err
			}
			return printSQL(cmd.OutOrStdout(), append(stmts, app...))
		},
	}
	f.register(cmd)
	cmd.Flags().BoolVar(&withOwner, "with-owner", false, "also print the SQL creating the owner role")
	return cmd
}

func printSQL(w io.Writer, stmts []string) error {
	for _, s := range stmts {
		if _, err := fmt.Fprintf(w, "%s;\n", s); err != nil {
			return err
		}
	}
	return nil
}

// envValue reads a required environment variable.
func envValue(name string) (string, error) {
	if name == "" {
		return "", errors.New("no environment variable named")
	}
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("environment variable %s is empty", name)
	}
	return v, nil
}

func newApplyCmd() *cobra.Command {
	var f roleFlags
	var adminEnv, passwordEnv, ownerPasswordEnv string
	var createOwner bool
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Provision an app's login with an admin connection",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			p, err := f.provisioning()
			if err != nil {
				return err
			}
			adminURL, err := envValue(adminEnv)
			if err != nil {
				return fmt.Errorf("--admin-url-env: %w", err)
			}
			pool, err := pgxpool.New(ctx, adminURL)
			if err != nil {
				return fmt.Errorf("admin connection: %w", err)
			}
			defer pool.Close()
			if createOwner {
				var pw multiapp.PasswordSource
				if ownerPasswordEnv != "" {
					pw = multiapp.PasswordFromEnv(ownerPasswordEnv)
				}
				if err := multiapp.ApplyOwnerRole(ctx, pool, f.owner, pw); err != nil {
					return err
				}
			}
			var pw multiapp.PasswordSource
			if passwordEnv != "" {
				pw = multiapp.PasswordFromEnv(passwordEnv)
			}
			if err := multiapp.ApplyRoleProvisioning(ctx, pool, p, pw); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "provisioned role %s for schema %s\n", p.Role, p.Schema)
			return err
		},
	}
	f.register(cmd)
	cmd.Flags().StringVar(&adminEnv, "admin-url-env", "ADMIN_DATABASE_URL", "environment variable holding the admin connection string")
	cmd.Flags().StringVar(&passwordEnv, "password-env", "", "environment variable holding the app role's password (omit for IAM authentication)")
	cmd.Flags().BoolVar(&createOwner, "create-owner", false, "also create the owner role if missing")
	cmd.Flags().StringVar(&ownerPasswordEnv, "owner-password-env", "", "environment variable holding the owner role's password (with --create-owner)")
	return cmd
}

func newVerifyCmd() *cobra.Command {
	var logins []string
	var owners []string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Check that each app's login is confined to its own schema",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(logins) == 0 {
				return errors.New("set at least one --login slug=ENV_VAR")
			}
			return verify(cmd.Context(), cmd.OutOrStdout(), logins, owners)
		},
	}
	cmd.Flags().StringArrayVar(&logins, "login", nil, "app login as slug=ENV_VAR, the variable holding its connection string (repeatable)")
	cmd.Flags().StringSliceVar(&owners, "owner", nil, "migration (owner) role (repeatable)")
	return cmd
}

func verify(ctx context.Context, out io.Writer, logins, owners []string) error {
	var apps []multiapp.AppDatabaseLogin
	defer func() {
		for _, a := range apps {
			a.Pool.Close()
		}
	}()
	for _, l := range logins {
		slug, env, ok := strings.Cut(l, "=")
		if !ok || slug == "" {
			return fmt.Errorf("--login %q: want slug=ENV_VAR", l)
		}
		url, err := envValue(env)
		if err != nil {
			return fmt.Errorf("--login %s: %w", slug, err)
		}
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			return fmt.Errorf("--login %s: %w", slug, err)
		}
		apps = append(apps, multiapp.AppDatabaseLogin{Slug: slug, Schema: multiapp.SchemaFromAppSlug(slug), Pool: pool})
	}
	if err := multiapp.CheckDatabaseIsolation(ctx, apps, owners...); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "%d app logins are confined to their schemas\n", len(apps))
	return err
}
