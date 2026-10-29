package multiapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DefaultSharedReadTables are the shared SystemForge identity tables an app
// reads when it authorizes requests in process against the identity
// database: who a principal is, which organizations it belongs to, and the
// app roles and resource grants it holds (the tables authz mode rbac
// reads). RoleProvisioning grants SELECT on them by default, when
// SharedReadTables is nil.
//
// Tables that hold secrets or drive sign-in are deliberately absent and
// must stay with the identity service's own login: credentials, OAuth app
// secrets, authorization codes and tokens, principal (API key) token
// hashes, SCIM tokens, login states and sessions, invites, signup and
// external identities.
var DefaultSharedReadTables = []string{
	"sf_principals",
	"sf_organizations",
	"sf_principal_memberships",
	"sf_app_roles",
	"sf_resource_grants",
}

// RoleProvisioning describes the database login of one app: a role that
// can log in, use its own schema and nothing else of the other apps.
type RoleProvisioning struct {
	// Schema is the app's schema, normally SchemaFromAppSlug(slug).
	// Required.
	Schema string

	// Role is the app's login role. Required.
	Role string

	// OwnerRole is the migration login: it owns Schema and creates its
	// tables, and the app role receives privileges on the tables it
	// creates through default privileges. It must differ from Role, and
	// the login that applies the SQL must be able to act as it (a
	// superuser, or a member of OwnerRole). Required.
	OwnerRole string

	// Database, when set, is granted CONNECT to Role.
	Database string

	// ReadOnly limits Role to SELECT on its schema's tables. By default
	// it gets SELECT, INSERT, UPDATE and DELETE.
	ReadOnly bool

	// SharedSchema is the schema holding the shared SystemForge tables.
	// Default "public".
	SharedSchema string

	// SharedReadTables are tables in SharedSchema Role may read (SELECT
	// only). Nil, the default, means DefaultSharedReadTables; a non-nil
	// empty slice (NoSharedReadTables) grants none, for an app that does
	// not read the identity tables. A non-empty list replaces the
	// default, so append to DefaultSharedReadTables to add tables. Tables
	// that do not exist yet are skipped, so apply the SQL again after the
	// identity migrations create them.
	SharedReadTables []string

	// MemberOf lists roles Role is made a member of, for example rds_iam
	// for IAM database authentication on Amazon RDS. Never list another
	// app's role or OwnerRole: the isolation check rejects it.
	MemberOf []string
}

// RestrictedSharedTables are the shared SystemForge tables an app login is
// never granted, even when SharedReadTables names them: they hold
// credentials, secrets, tokens, sign-in sessions and state, invitations
// and claim codes, and external identities. RoleProvisioning refuses a
// SharedReadTables entry listed here.
var RestrictedSharedTables = []string{
	"sf_client_assertion_jtis",
	"sf_credentials",
	"sf_external_identities",
	"sf_invites",
	"sf_login_sessions",
	"sf_login_states",
	"sf_manager_claims",
	"sf_manager_invites",
	"sf_oauth_app_secrets",
	"sf_oauth_auth_codes",
	"sf_oauth_tokens",
	"sf_principal_tokens",
	"sf_scim_tokens",
	"sf_signup_allowances",
	"sf_signup_code_redemptions",
	"sf_signup_codes",
	"sf_signup_invites",
	"sf_signup_waitlist",
	"sf_verification_tokens",
}

// NoSharedReadTables is a SharedReadTables value that grants no shared
// table.
var NoSharedReadTables = []string{}

// sharedTables returns the shared tables Role may read: SharedReadTables,
// or DefaultSharedReadTables when it is nil.
func (p RoleProvisioning) sharedTables() []string {
	if p.SharedReadTables == nil {
		return DefaultSharedReadTables
	}
	return p.SharedReadTables
}

func (p RoleProvisioning) sharedSchema() string {
	if p.SharedSchema == "" {
		return "public"
	}
	return p.SharedSchema
}

func (p RoleProvisioning) validate() error {
	if err := checkName("schema", p.Schema); err != nil {
		return err
	}
	if err := checkName("role", p.Role); err != nil {
		return err
	}
	if err := checkName("owner role", p.OwnerRole); err != nil {
		return err
	}
	if p.Role == p.OwnerRole {
		return errors.New("multiapp: the app role and the owner (migration) role must differ")
	}
	if p.Database != "" {
		if err := checkName("database", p.Database); err != nil {
			return err
		}
	}
	shared := p.sharedSchema()
	if err := checkName("shared schema", shared); err != nil {
		return err
	}
	if shared == p.Schema {
		return errors.New("multiapp: the shared schema must differ from the app schema")
	}
	for _, t := range p.sharedTables() {
		if err := checkName("shared table", t); err != nil {
			return err
		}
		if slices.Contains(RestrictedSharedTables, t) {
			return fmt.Errorf("multiapp: shared table %q holds secrets or sign-in state and is never granted to an app login", t)
		}
	}
	for _, r := range p.MemberOf {
		if err := checkName("role", r); err != nil {
			return err
		}
		if r == p.OwnerRole || r == p.Role {
			return fmt.Errorf("multiapp: role %q must not be a member of %q", p.Role, r)
		}
	}
	return nil
}

// SQL returns the statements that provision the app's login, in order.
// They are idempotent, so they can be applied again, for example after new
// shared tables appear. They never contain a password; ApplyRoleProvisioning
// sets one.
//
// The statements:
//
//   - create Role (if missing) with LOGIN NOINHERIT NOSUPERUSER NOCREATEDB
//     NOCREATEROLE NOBYPASSRLS NOREPLICATION, and reset LOGIN, NOINHERIT,
//     NOCREATEDB and NOCREATEROLE on an existing one (changing SUPERUSER or
//     BYPASSRLS needs a superuser, so the isolation check reports those
//     instead);
//   - create Schema owned by OwnerRole and revoke PUBLIC's access to it;
//   - grant Role USAGE on Schema and table, sequence and function
//     privileges on what exists, plus default privileges on what OwnerRole
//     creates later;
//   - revoke CREATE on schema public from PUBLIC and EXECUTE on OwnerRole's
//     future functions from PUBLIC;
//   - grant SELECT on the shared tables (SharedReadTables, by default
//     DefaultSharedReadTables), and set Role's search_path to
//     Schema and SharedSchema.
func (p RoleProvisioning) SQL() ([]string, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	role := quoteIdent(p.Role)
	owner := quoteIdent(p.OwnerRole)
	schema := quoteIdent(p.Schema)
	shared := quoteIdent(p.sharedSchema())
	tablePrivs := "SELECT, INSERT, UPDATE, DELETE"
	seqPrivs := "USAGE, SELECT"
	if p.ReadOnly {
		tablePrivs = "SELECT"
		seqPrivs = "SELECT"
	}

	stmts := []string{
		// The role name is validated, so it cannot end the dollar quote.
		fmt.Sprintf(`DO $sf$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = %s) THEN CREATE ROLE %s WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION; END IF; END $sf$`,
			quoteLiteral(p.Role), role),
		fmt.Sprintf("ALTER ROLE %s WITH LOGIN NOINHERIT NOCREATEDB NOCREATEROLE", role),
	}
	if p.Database != "" {
		stmts = append(stmts, fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", quoteIdent(p.Database), role))
	}
	stmts = append(stmts,
		fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s AUTHORIZATION %s", schema, owner),
		fmt.Sprintf("ALTER SCHEMA %s OWNER TO %s", schema, owner),
		fmt.Sprintf("REVOKE ALL ON SCHEMA %s FROM PUBLIC", schema),
		fmt.Sprintf("REVOKE ALL ON ALL TABLES IN SCHEMA %s FROM PUBLIC", schema),
		fmt.Sprintf("REVOKE ALL ON ALL SEQUENCES IN SCHEMA %s FROM PUBLIC", schema),
		fmt.Sprintf("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %s FROM PUBLIC", schema),
		fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s", schema, role),
		fmt.Sprintf("GRANT %s ON ALL TABLES IN SCHEMA %s TO %s", tablePrivs, schema, role),
		fmt.Sprintf("GRANT %s ON ALL SEQUENCES IN SCHEMA %s TO %s", seqPrivs, schema, role),
		fmt.Sprintf("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA %s TO %s", schema, role),
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT %s ON TABLES TO %s", owner, schema, tablePrivs, role),
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT %s ON SEQUENCES TO %s", owner, schema, seqPrivs, role),
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA %s GRANT EXECUTE ON FUNCTIONS TO %s", owner, schema, role),
		// Per-schema default privileges only add to the global ones, so
		// PUBLIC's EXECUTE on new functions is revoked globally.
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES FOR ROLE %s REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC", owner),
		// Every app's search_path ends in the shared schema; nobody may
		// plant objects there.
		"REVOKE CREATE ON SCHEMA public FROM PUBLIC",
		fmt.Sprintf("GRANT USAGE ON SCHEMA %s TO %s", shared, role),
	)
	for _, t := range p.sharedTables() {
		qualified := quoteQualified(p.sharedSchema(), t)
		stmts = append(stmts, fmt.Sprintf(
			`DO $sf$ BEGIN IF to_regclass(%s) IS NOT NULL THEN GRANT SELECT ON TABLE %s TO %s; END IF; END $sf$`,
			quoteLiteral(qualified), qualified, role))
	}
	for _, r := range p.MemberOf {
		stmts = append(stmts, fmt.Sprintf("GRANT %s TO %s", quoteIdent(r), role))
	}
	stmts = append(stmts, fmt.Sprintf("ALTER ROLE %s SET search_path TO %s, %s", role, schema, shared))
	return stmts, nil
}

// OwnerRoleSQL returns statements that create the migration (owner) login
// if it is missing: LOGIN, with no superuser, role creation, database
// creation, replication or RLS bypass. Set its password with
// SetRolePassword.
func OwnerRoleSQL(owner string) ([]string, error) {
	if err := checkName("owner role", owner); err != nil {
		return nil, err
	}
	return []string{
		fmt.Sprintf(`DO $sf$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = %s) THEN CREATE ROLE %s WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION; END IF; END $sf$`,
			quoteLiteral(owner), quoteIdent(owner)),
	}, nil
}

// PasswordSource returns a role's password, for example from a secret
// manager or the environment. It is called once, when the password is set.
type PasswordSource func(ctx context.Context) (string, error)

// PasswordFromEnv reads the password from the environment variable name.
// An unset or empty variable is an error.
func PasswordFromEnv(name string) PasswordSource {
	return func(context.Context) (string, error) {
		v := os.Getenv(name)
		if v == "" {
			return "", fmt.Errorf("multiapp: environment variable %s is empty", name)
		}
		return v, nil
	}
}

// Execer runs a statement. pgx.Tx, *pgx.Conn and *pgxpool.Pool satisfy it.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// TxBeginner starts a transaction. *pgx.Conn and *pgxpool.Pool satisfy it.
type TxBeginner interface {
	Begin(ctx context.Context) (pgx.Tx, error)
}

// ApplyRoleProvisioning runs p's SQL in one transaction on db, which must be
// an admin (or migration-capable) login, then sets the role's password from
// password when it is not nil. Leave password nil for roles that sign in
// without one, such as IAM database authentication.
func ApplyRoleProvisioning(ctx context.Context, db TxBeginner, p RoleProvisioning, password PasswordSource) error {
	stmts, err := p.SQL()
	if err != nil {
		return err
	}
	return applyStatements(ctx, db, stmts, p.Role, password)
}

// ApplyOwnerRole creates the migration (owner) login on db and sets its
// password from password when it is not nil.
func ApplyOwnerRole(ctx context.Context, db TxBeginner, owner string, password PasswordSource) error {
	stmts, err := OwnerRoleSQL(owner)
	if err != nil {
		return err
	}
	return applyStatements(ctx, db, stmts, owner, password)
}

func applyStatements(ctx context.Context, db TxBeginner, stmts []string, role string, password PasswordSource) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("multiapp: begin: %w", err)
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s); err != nil {
			return errors.Join(fmt.Errorf("multiapp: provisioning role %s: %s: %w", role, firstLine(s), err), tx.Rollback(ctx))
		}
	}
	if password != nil {
		if err := setRolePassword(ctx, tx, role, password); err != nil {
			return errors.Join(err, tx.Rollback(ctx))
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("multiapp: commit: %w", err)
	}
	return nil
}

// SetRolePassword sets role's password from password. The statement
// carries a SCRAM-SHA-256 verifier computed here, never the password, so
// server statement logs do not record it; errors never include it either.
func SetRolePassword(ctx context.Context, db Execer, role string, password PasswordSource) error {
	if password == nil {
		return errors.New("multiapp: no password source")
	}
	return setRolePassword(ctx, db, role, password)
}

func setRolePassword(ctx context.Context, db Execer, role string, password PasswordSource) error {
	if err := checkName("role", role); err != nil {
		return err
	}
	pw, err := password(ctx)
	if err != nil {
		return fmt.Errorf("multiapp: password for role %s: %w", role, err)
	}
	verifier, err := scramSHA256Verifier(pw)
	if err != nil {
		return fmt.Errorf("multiapp: password for role %s: %w", role, err)
	}
	if _, err := db.Exec(ctx, fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s", quoteIdent(role), quoteLiteral(verifier))); err != nil {
		// The error comes from the server and names no password; the
		// statement, which carries the verifier, is not included.
		return fmt.Errorf("multiapp: setting the password of role %s: %w", role, err)
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
