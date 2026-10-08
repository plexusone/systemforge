package rls

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/plexusone/systemforge/session/middleware"
)

// Middleware provides HTTP middleware that automatically sets PostgreSQL
// RLS context from JWT claims.
type Middleware struct {
	db     *sql.DB
	helper *Helper
}

// NewMiddleware creates a new RLS middleware.
func NewMiddleware(db *sql.DB, cfg *Config) *Middleware {
	return &Middleware{
		db:     db,
		helper: NewHelper(cfg),
	}
}

// SetRLSContext returns middleware that puts the authenticated caller's
// organization and principal on the request context, where WithTx and
// WithTenant pick them up to scope a transaction.
//
// It does not touch the database. PostgreSQL's SET LOCAL lasts only for a
// transaction, and a middleware that runs before the handler has none, so
// setting the variables here would scope nothing. Do the work through WithTx.
//
// This middleware should be used AFTER authentication middleware.
//
// Usage with Chi:
//
//	r.Use(middleware.ChiAuth(jwtService))
//	r.Use(rlsMiddleware.SetRLSContext())
func (m *Middleware) SetRLSContext() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get claims from context (set by auth middleware)
			claims := middleware.ClaimsFromContext(ctx)
			if claims == nil {
				next.ServeHTTP(w, r)
				return
			}

			if claims.OrganizationID != nil {
				ctx = ContextWithTenant(ctx, *claims.OrganizationID)
			}
			ctx = ContextWithUser(ctx, claims.PrincipalID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WithTx runs fn in a transaction scoped to the tenant and user that
// SetRLSContext put on ctx. The session variables are set inside the
// transaction, which is the only place they take effect.
func (m *Middleware) WithTx(ctx context.Context, fn TxFunc) error {
	return WithTenant(ctx, m.db, m.helper, TenantIDFromContext(ctx), UserIDFromContext(ctx), fn)
}

// RequireTenant returns middleware that ensures a tenant context is present.
// Returns 403 Forbidden if no organization is in the JWT claims.
func (m *Middleware) RequireTenant() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := middleware.ClaimsFromContext(r.Context())
			if claims == nil || claims.OrganizationID == nil {
				http.Error(w, "tenant context required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// DBWithRLS wraps a database connection to automatically set RLS context
// for each connection obtained from the pool.
type DBWithRLS struct {
	*sql.DB
	helper *Helper
}

// NewDBWithRLS creates a new RLS-aware database wrapper.
func NewDBWithRLS(db *sql.DB, cfg *Config) *DBWithRLS {
	return &DBWithRLS{
		DB:     db,
		helper: NewHelper(cfg),
	}
}
