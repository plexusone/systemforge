package rls

import (
	"context"
	"database/sql"
	"fmt"
)

// EntHook provides integration with Ent ORM for automatic RLS context.
//
// Usage with Ent:
//
//	hook := rls.NewEntHook(db, rls.DefaultConfig())
//
//	client := ent.NewClient(
//	    ent.Driver(drv),
//	    ent.Hook(hook.SetContext()),
//	)
type EntHook struct {
	db     *sql.DB
	helper *Helper
}

// NewEntHook creates a new Ent RLS hook.
func NewEntHook(db *sql.DB, cfg *Config) *EntHook {
	return &EntHook{
		db:     db,
		helper: NewHelper(cfg),
	}
}

// SetContextFromContext sets RLS context using tenant/user from Go context.
//
// Deprecated: it sets the variables on the pool, not on a transaction, where
// SET LOCAL has no effect, so it now returns ErrNotInTransaction whenever a
// tenant or user is present. Run the work in rls.WithTenant instead.
func (h *EntHook) SetContextFromContext(ctx context.Context) error {
	tenantID := TenantIDFromContext(ctx)
	userID := UserIDFromContext(ctx)

	if tenantID.String() != "00000000-0000-0000-0000-000000000000" {
		if err := h.helper.SetTenant(ctx, h.db, tenantID.String()); err != nil {
			return fmt.Errorf("setting tenant: %w", err)
		}
	}

	if userID.String() != "00000000-0000-0000-0000-000000000000" {
		if err := h.helper.SetUser(ctx, h.db, userID.String()); err != nil {
			return fmt.Errorf("setting user: %w", err)
		}
	}

	return nil
}

// EntDriver wraps an Ent SQL driver to automatically set RLS context.
// This ensures RLS is set for every database operation.
type EntDriver struct {
	// Underlying driver (implement as needed for your Ent setup)
	helper *Helper
}

// NewEntDriver creates a new RLS-aware Ent driver wrapper.
func NewEntDriver(cfg *Config) *EntDriver {
	return &EntDriver{
		helper: NewHelper(cfg),
	}
}

// ContextInjector creates a function that can be used to inject RLS context
// into database connections. This is useful for connection pool hooks.
type ContextInjector struct {
	helper *Helper
}

// NewContextInjector creates a new context injector.
func NewContextInjector(cfg *Config) *ContextInjector {
	return &ContextInjector{helper: NewHelper(cfg)}
}

// InjectContext sets RLS session variables on a connection.
//
// Deprecated: SET LOCAL on a connection outside a transaction has no effect,
// so it returns ErrNotInTransaction whenever a tenant or user is present. Run
// the work in rls.WithTenant instead.
func (ci *ContextInjector) InjectContext(ctx context.Context, conn *sql.Conn) error {
	tenantID := TenantIDFromContext(ctx)
	userID := UserIDFromContext(ctx)

	if tenantID.String() != "00000000-0000-0000-0000-000000000000" {
		if err := ci.helper.SetTenant(ctx, conn, tenantID.String()); err != nil {
			return fmt.Errorf("setting tenant: %w", err)
		}
	}

	if userID.String() != "00000000-0000-0000-0000-000000000000" {
		if err := ci.helper.SetUser(ctx, conn, userID.String()); err != nil {
			return fmt.Errorf("setting user: %w", err)
		}
	}

	return nil
}

// ConnWithRLS wraps sql.Conn to ensure RLS context is set.
type ConnWithRLS struct {
	*sql.Conn
	ctx    context.Context
	helper *Helper
}

// NewConnWithRLS wraps a connection with RLS context injection.
//
// Deprecated: SET LOCAL on a connection outside a transaction has no effect,
// so it returns ErrNotInTransaction whenever a tenant or user is present. Run
// the work in rls.WithTenant instead.
func NewConnWithRLS(ctx context.Context, conn *sql.Conn, cfg *Config) (*ConnWithRLS, error) {
	c := &ConnWithRLS{
		Conn:   conn,
		ctx:    ctx,
		helper: NewHelper(cfg),
	}

	// Set RLS context immediately
	tenantID := TenantIDFromContext(ctx)
	userID := UserIDFromContext(ctx)

	if tenantID.String() != "00000000-0000-0000-0000-000000000000" {
		if err := c.helper.SetTenant(ctx, conn, tenantID.String()); err != nil {
			return nil, fmt.Errorf("setting tenant: %w", err)
		}
	}

	if userID.String() != "00000000-0000-0000-0000-000000000000" {
		if err := c.helper.SetUser(ctx, conn, userID.String()); err != nil {
			return nil, fmt.Errorf("setting user: %w", err)
		}
	}

	return c, nil
}

// GetConnWithRLS gets a connection from the pool with RLS context set.
//
// Deprecated: see NewConnWithRLS.
func GetConnWithRLS(ctx context.Context, db *sql.DB, cfg *Config) (*ConnWithRLS, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}

	return NewConnWithRLS(ctx, conn, cfg)
}
