// Package rls provides PostgreSQL Row-Level Security helpers for SystemForge.
package rls

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrNotInTransaction is returned when a session variable is set through a
// *sql.DB or *sql.Conn. SET LOCAL lasts only until the end of the current
// transaction; outside one it is a no-op that the database reports as a
// warning, so the query that follows would run with no tenant. Run the work in
// a transaction, for example with WithTenant.
var ErrNotInTransaction = errors.New("rls: SET LOCAL needs a transaction, use rls.WithTenant")

// requireTransaction refuses executors that cannot hold a SET LOCAL.
func requireTransaction(db Executor) error {
	switch db.(type) {
	case *sql.DB, *sql.Conn:
		return ErrNotInTransaction
	}
	return nil
}

// Config holds RLS configuration.
type Config struct {
	// TenantColumn is the name of the column used for tenant isolation.
	// Defaults to "organization_id".
	TenantColumn string

	// UserColumn is the name of the column used for user identification.
	// Defaults to "user_id".
	UserColumn string

	// SessionVariable is the PostgreSQL session variable for the current tenant.
	// Defaults to "app.current_tenant".
	SessionVariable string

	// UserSessionVariable is the PostgreSQL session variable for the current user.
	// Defaults to "app.current_user".
	UserSessionVariable string
}

// DefaultConfig returns the default RLS configuration.
func DefaultConfig() *Config {
	return &Config{
		TenantColumn:        "organization_id",
		UserColumn:          "user_id",
		SessionVariable:     "app.current_tenant",
		UserSessionVariable: "app.current_user",
	}
}

// Helper provides RLS operations for PostgreSQL.
type Helper struct {
	config *Config
}

// NewHelper creates a new RLS helper with the given configuration.
func NewHelper(cfg *Config) *Helper {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Helper{config: cfg}
}

// SetTenant sets the current tenant in the database session.
// This should be called at the start of each request/transaction.
//
// db must be a transaction: SetTenant returns ErrNotInTransaction for a
// *sql.DB or *sql.Conn.
func (h *Helper) SetTenant(ctx context.Context, db Executor, tenantID string) error {
	if err := requireTransaction(db); err != nil {
		return err
	}
	query := fmt.Sprintf("SET LOCAL %s = $1", h.config.SessionVariable)
	_, err := db.ExecContext(ctx, query, tenantID)
	if err != nil {
		return fmt.Errorf("setting tenant: %w", err)
	}
	return nil
}

// SetUser sets the current user in the database session.
//
// db must be a transaction, as for SetTenant.
func (h *Helper) SetUser(ctx context.Context, db Executor, userID string) error {
	if err := requireTransaction(db); err != nil {
		return err
	}
	query := fmt.Sprintf("SET LOCAL %s = $1", h.config.UserSessionVariable)
	_, err := db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("setting user: %w", err)
	}
	return nil
}

// SetContext sets both tenant and user in the database session.
func (h *Helper) SetContext(ctx context.Context, db Executor, tenantID, userID string) error {
	if err := h.SetTenant(ctx, db, tenantID); err != nil {
		return err
	}
	return h.SetUser(ctx, db, userID)
}

// ClearContext clears the tenant and user session variables.
func (h *Helper) ClearContext(ctx context.Context, db Executor) error {
	queries := []string{
		fmt.Sprintf("RESET %s", h.config.SessionVariable),
		fmt.Sprintf("RESET %s", h.config.UserSessionVariable),
	}

	for _, query := range queries {
		if _, err := db.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("clearing context: %w", err)
		}
	}
	return nil
}

// Executor is an interface for executing SQL queries.
// Implemented by *sql.DB, *sql.Tx, and similar types.
type Executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// PolicySQL generates SQL for creating an RLS policy.
type PolicySQL struct {
	tableName  string
	policyName string
	config     *Config
}

// NewPolicySQL creates a new PolicySQL builder.
func NewPolicySQL(tableName, policyName string, cfg *Config) *PolicySQL {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &PolicySQL{
		tableName:  tableName,
		policyName: policyName,
		config:     cfg,
	}
}

// EnableRLS returns SQL to enable RLS on the table.
func (p *PolicySQL) EnableRLS() string {
	return fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY", p.tableName)
}

// ForceRLS returns SQL to force RLS even for table owners.
func (p *PolicySQL) ForceRLS() string {
	return fmt.Sprintf("ALTER TABLE %s FORCE ROW LEVEL SECURITY", p.tableName)
}

// CreateSelectPolicy returns SQL to create a SELECT policy.
func (p *PolicySQL) CreateSelectPolicy() string {
	return fmt.Sprintf(`
CREATE POLICY %s_select ON %s
    FOR SELECT
    USING (%s::text = current_setting('%s', true))`,
		p.policyName, p.tableName, p.config.TenantColumn, p.config.SessionVariable)
}

// CreateInsertPolicy returns SQL to create an INSERT policy.
func (p *PolicySQL) CreateInsertPolicy() string {
	return fmt.Sprintf(`
CREATE POLICY %s_insert ON %s
    FOR INSERT
    WITH CHECK (%s::text = current_setting('%s', true))`,
		p.policyName, p.tableName, p.config.TenantColumn, p.config.SessionVariable)
}

// CreateUpdatePolicy returns SQL to create an UPDATE policy.
func (p *PolicySQL) CreateUpdatePolicy() string {
	return fmt.Sprintf(`
CREATE POLICY %s_update ON %s
    FOR UPDATE
    USING (%s::text = current_setting('%s', true))
    WITH CHECK (%s::text = current_setting('%s', true))`,
		p.policyName, p.tableName,
		p.config.TenantColumn, p.config.SessionVariable,
		p.config.TenantColumn, p.config.SessionVariable)
}

// CreateDeletePolicy returns SQL to create a DELETE policy.
func (p *PolicySQL) CreateDeletePolicy() string {
	return fmt.Sprintf(`
CREATE POLICY %s_delete ON %s
    FOR DELETE
    USING (%s::text = current_setting('%s', true))`,
		p.policyName, p.tableName, p.config.TenantColumn, p.config.SessionVariable)
}

// CreateAllPolicies returns SQL to enable RLS and create all CRUD policies.
func (p *PolicySQL) CreateAllPolicies() string {
	return fmt.Sprintf(`%s;
%s;
%s;
%s;
%s;
%s;`,
		p.EnableRLS(),
		p.ForceRLS(),
		p.CreateSelectPolicy(),
		p.CreateInsertPolicy(),
		p.CreateUpdatePolicy(),
		p.CreateDeletePolicy())
}

// DropPolicy returns SQL to drop a policy.
func (p *PolicySQL) DropPolicy(operation string) string {
	return fmt.Sprintf("DROP POLICY IF EXISTS %s_%s ON %s",
		p.policyName, operation, p.tableName)
}

// DropAllPolicies returns SQL to drop all policies and disable RLS.
func (p *PolicySQL) DropAllPolicies() string {
	return fmt.Sprintf(`%s;
%s;
%s;
%s;
ALTER TABLE %s DISABLE ROW LEVEL SECURITY;`,
		p.DropPolicy("select"),
		p.DropPolicy("insert"),
		p.DropPolicy("update"),
		p.DropPolicy("delete"),
		p.tableName)
}

// BypassRLS returns SQL to grant RLS bypass to a role.
// This is typically used for admin/migration roles.
func BypassRLS(roleName string) string {
	return fmt.Sprintf("ALTER ROLE %s BYPASSRLS", roleName)
}

// NoBypassRLS returns SQL to revoke RLS bypass from a role.
func NoBypassRLS(roleName string) string {
	return fmt.Sprintf("ALTER ROLE %s NOBYPASSRLS", roleName)
}
