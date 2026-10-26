package multiapp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AppDatabaseLogin is one app's schema and, when the app has a database
// login of its own, the pool connected with it.
type AppDatabaseLogin struct {
	// Slug names the app in violations.
	Slug string

	// Schema is the app's schema.
	Schema string

	// Pool is connected with the app's own login. Leave it nil for an app
	// on the shared development login: its schema is still checked as one
	// the other apps must not reach, but its login is not checked.
	Pool *pgxpool.Pool
}

// IsolationViolation is one way an app's login reaches beyond its schema.
type IsolationViolation struct {
	App     string
	Problem string
}

// IsolationError lists the isolation violations found. Its message names
// apps, roles and schemas, never a password or connection string.
type IsolationError struct {
	Violations []IsolationViolation
}

func (e *IsolationError) Error() string {
	var b strings.Builder
	b.WriteString("multiapp: database isolation check failed:")
	for _, v := range e.Violations {
		fmt.Fprintf(&b, "\n  app %q: %s", v.App, v.Problem)
	}
	return b.String()
}

// sqlStateInsufficientPrivilege is PostgreSQL's "permission denied".
const sqlStateInsufficientPrivilege = "42501"

// alwaysForbiddenRoles are predefined roles that read or write every table
// regardless of schema privileges (PostgreSQL 14 and later).
var alwaysForbiddenRoles = []string{"pg_read_all_data", "pg_write_all_data"}

// CheckDatabaseIsolation verifies that each app login in apps (those with a
// Pool) is confined to its own schema:
//
//   - it is not a superuser and has neither BYPASSRLS nor CREATEROLE;
//   - it is not the login of another app, does not own any app schema,
//     and is not a member of another app's role, of an owner role (the
//     owners of the app schemas and ownerRoles, the migration logins), of
//     a superuser or BYPASSRLS role, or of pg_read_all_data or
//     pg_write_all_data;
//   - it has USAGE on its own schema;
//   - it has neither USAGE nor CREATE on another app's schema, and reading
//     a table there, creating a table there, and SET ROLE to another app's
//     role or an owner role all fail with permission denied (the probes
//     run in transactions that are rolled back);
//   - it cannot create objects in schema public, which every app's
//     search_path includes;
//   - its default search_path does not name or reach another app's schema.
//
// It returns an *IsolationError listing every violation, or another error
// when the check itself could not run.
func CheckDatabaseIsolation(ctx context.Context, apps []AppDatabaseLogin, ownerRoles ...string) error {
	for _, a := range apps {
		if err := checkName("schema", a.Schema); err != nil {
			return fmt.Errorf("multiapp: app %q: %w", a.Slug, err)
		}
	}
	// The login role of every app with a pool.
	logins := make(map[string]string, len(apps))
	for _, a := range apps {
		if a.Pool == nil {
			continue
		}
		var user string
		if err := a.Pool.QueryRow(ctx, "SELECT current_user").Scan(&user); err != nil {
			return fmt.Errorf("multiapp: app %q: connecting with its database login: %w", a.Slug, err)
		}
		logins[a.Slug] = user
	}

	var violations []IsolationViolation
	for _, a := range apps {
		if a.Pool == nil {
			continue
		}
		problems, err := checkAppLogin(ctx, a, apps, logins, ownerRoles)
		if err != nil {
			return fmt.Errorf("multiapp: app %q: isolation check: %w", a.Slug, err)
		}
		for _, p := range problems {
			violations = append(violations, IsolationViolation{App: a.Slug, Problem: p})
		}
	}
	if len(violations) > 0 {
		return &IsolationError{Violations: violations}
	}
	return nil
}

func checkAppLogin(ctx context.Context, app AppDatabaseLogin, apps []AppDatabaseLogin, logins map[string]string, ownerRoles []string) ([]string, error) {
	conn, err := app.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()
	c := conn.Conn()
	self := logins[app.Slug]
	var problems []string
	addf := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	// Role attributes.
	var super, bypassRLS, createRole bool
	if err := c.QueryRow(ctx,
		"SELECT rolsuper, rolbypassrls, rolcreaterole FROM pg_catalog.pg_roles WHERE rolname = current_user",
	).Scan(&super, &bypassRLS, &createRole); err != nil {
		return nil, fmt.Errorf("reading role attributes: %w", err)
	}
	if super {
		addf("login role %q is a superuser", self)
	}
	if bypassRLS {
		addf("login role %q has BYPASSRLS", self)
	}
	if createRole {
		addf("login role %q has CREATEROLE", self)
	}

	// Schemas: which exist, and who owns them.
	var otherSchemas, otherRoles []string
	for _, o := range apps {
		if o.Slug == app.Slug {
			continue
		}
		if o.Schema != app.Schema {
			otherSchemas = append(otherSchemas, o.Schema)
		} else {
			addf("shares schema %q with app %q", o.Schema, o.Slug)
		}
		if r, ok := logins[o.Slug]; ok {
			if r == self {
				addf("shares database login %q with app %q", self, o.Slug)
			} else {
				otherRoles = append(otherRoles, r)
			}
		}
	}
	allSchemas := append([]string{app.Schema}, otherSchemas...)
	owners := map[string]string{}
	rows, err := c.Query(ctx,
		"SELECT nspname, pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname = ANY($1)",
		allSchemas)
	if err != nil {
		return nil, fmt.Errorf("reading schema owners: %w", err)
	}
	for rows.Next() {
		var n, o string
		if err := rows.Scan(&n, &o); err != nil {
			rows.Close()
			return nil, err
		}
		owners[n] = o
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading schema owners: %w", err)
	}

	ownerSet := slices.Clone(ownerRoles)
	for _, s := range allSchemas {
		o, ok := owners[s]
		if !ok {
			continue
		}
		if o == self {
			addf("login role %q owns schema %q; the migration login should own app schemas", self, s)
			continue
		}
		ownerSet = append(ownerSet, o)
	}
	slices.Sort(ownerSet)
	ownerSet = slices.Compact(ownerSet)
	for _, o := range ownerRoles {
		if o == self {
			addf("login role %q is the migration (owner) login", self)
		}
	}

	// Memberships that lend another app's or an owner's privileges.
	forbidden := slices.Concat(otherRoles, ownerSet, alwaysForbiddenRoles)
	mrows, err := c.Query(ctx, `
		SELECT b.rolname, b.rolsuper, b.rolbypassrls
		FROM pg_catalog.pg_roles b
		WHERE b.rolname <> current_user
		  AND pg_catalog.pg_has_role(current_user, b.oid, 'MEMBER')
		  AND (b.rolsuper OR b.rolbypassrls OR b.rolname = ANY($1))
		ORDER BY b.rolname`, forbidden)
	if err != nil {
		return nil, fmt.Errorf("reading role memberships: %w", err)
	}
	for mrows.Next() {
		var name string
		var rsuper, rbypass bool
		if err := mrows.Scan(&name, &rsuper, &rbypass); err != nil {
			mrows.Close()
			return nil, err
		}
		switch {
		case rsuper:
			addf("login role %q is a member of superuser role %q", self, name)
		case rbypass:
			addf("login role %q is a member of BYPASSRLS role %q", self, name)
		case slices.Contains(otherRoles, name):
			addf("login role %q is a member of another app's role %q", self, name)
		case slices.Contains(ownerSet, name):
			addf("login role %q is a member of owner (migration) role %q", self, name)
		default:
			addf("login role %q is a member of %q, which reads or writes every table", self, name)
		}
	}
	if err := mrows.Err(); err != nil {
		return nil, fmt.Errorf("reading role memberships: %w", err)
	}

	// Its own schema.
	if _, ok := owners[app.Schema]; !ok {
		addf("schema %q does not exist; provision it with the migration login", app.Schema)
	} else {
		var usage bool
		if err := c.QueryRow(ctx, "SELECT has_schema_privilege($1, 'USAGE')", app.Schema).Scan(&usage); err != nil {
			return nil, err
		}
		if !usage {
			addf("login role %q has no USAGE on its own schema %q", self, app.Schema)
		}
	}

	// Other apps' schemas.
	for _, s := range otherSchemas {
		if _, ok := owners[s]; !ok {
			continue // not provisioned yet; its own app reports it
		}
		var usage, create bool
		if err := c.QueryRow(ctx, "SELECT has_schema_privilege($1, 'USAGE'), has_schema_privilege($1, 'CREATE')", s).Scan(&usage, &create); err != nil {
			return nil, err
		}
		if usage {
			addf("login role %q has USAGE on schema %q of another app", self, s)
		}
		if create {
			addf("login role %q has CREATE on schema %q of another app", self, s)
		}
		var table string
		err := c.QueryRow(ctx, `
			SELECT c.relname FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1 AND c.relkind IN ('r', 'p', 'v', 'm')
			ORDER BY c.relname LIMIT 1`, s).Scan(&table)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return nil, err
		default:
			if p, err := probeDenied(ctx, c, "SELECT 1 FROM "+quoteQualified(s, table)+" LIMIT 0"); err != nil {
				return nil, err
			} else if p != "" {
				addf("reading %s.%s of another app: %s", s, table, p)
			}
		}
		if p, err := probeDenied(ctx, c, "CREATE TABLE "+quoteQualified(s, "sf_isolation_probe")+" ()"); err != nil {
			return nil, err
		} else if p != "" {
			addf("creating a table in schema %q of another app: %s", s, p)
		}
	}
	for _, r := range slices.Concat(otherRoles, ownerSet) {
		if r == self {
			continue
		}
		if p, err := probeDenied(ctx, c, "SET LOCAL ROLE "+quoteIdent(r)); err != nil {
			return nil, err
		} else if p != "" {
			addf("SET ROLE %q: %s", r, p)
		}
	}

	// Schema public, on every app's search_path.
	var publicCreate bool
	if err := c.QueryRow(ctx,
		"SELECT EXISTS (SELECT FROM pg_catalog.pg_namespace WHERE nspname = 'public') AND has_schema_privilege('public', 'CREATE')",
	).Scan(&publicCreate); err != nil {
		return nil, err
	}
	if publicCreate {
		addf("login role %q can create objects in schema public, which every app's search_path includes", self)
	}

	// Default search_path.
	var searchPath string
	var effective []string
	if err := c.QueryRow(ctx, "SELECT current_setting('search_path'), current_schemas(false)").Scan(&searchPath, &effective); err != nil {
		return nil, err
	}
	for _, s := range otherSchemas {
		if slices.Contains(effective, s) || slices.Contains(searchPathNames(searchPath), s) {
			addf("default search_path %q reaches schema %q of another app", searchPath, s)
		}
	}
	return problems, nil
}

// probeDenied runs stmt in a transaction that is always rolled back. It
// returns "" when the statement fails with permission denied, and a
// description otherwise.
func probeDenied(ctx context.Context, c *pgx.Conn, stmt string) (string, error) {
	tx, err := c.Begin(ctx)
	if err != nil {
		return "", err
	}
	_, execErr := tx.Exec(ctx, stmt)
	if err := tx.Rollback(ctx); err != nil {
		return "", err
	}
	if execErr == nil {
		return "allowed, expected permission denied", nil
	}
	var pgErr *pgconn.PgError
	if errors.As(execErr, &pgErr) {
		if pgErr.Code == sqlStateInsufficientPrivilege {
			return "", nil
		}
		return fmt.Sprintf("failed with SQLSTATE %s (%s), expected permission denied", pgErr.Code, pgErr.Message), nil
	}
	return "", execErr
}

// searchPathNames splits a search_path setting into schema names, removing
// quotes.
func searchPathNames(setting string) []string {
	var names []string
	for _, part := range strings.Split(setting, ",") {
		n := strings.TrimSpace(part)
		if len(n) >= 2 && n[0] == '"' && n[len(n)-1] == '"' {
			n = strings.ReplaceAll(n[1:len(n)-1], `""`, `"`)
		}
		if n != "" {
			names = append(names, n)
		}
	}
	return names
}
