// Package connections wires connectionforge into SystemForge (ADR-017): an
// organization's connections to external services, stored on the platform
// database with row-level security, their credentials sealed by the keys
// package (ADR-013), deployment secrets read through omnivault, and
// authorization and audit through the platform's own.
package connections

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	cf "github.com/plexusone/connectionforge"
	"github.com/plexusone/connectionforge/sqlstore"
	"github.com/plexusone/keyforge"
	"github.com/plexusone/omnivault/vault"

	"github.com/plexusone/systemforge/authz"
	sfaudit "github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/keys"
	"github.com/plexusone/systemforge/rls"
)

// Purpose is the keys purpose credentials are sealed under. A deployment
// lists it in [keys.Options.Purposes].
const Purpose = keyforge.Purpose(cf.CredentialPurpose)

// TenantColumn is the column of connectionforge's tables that row-level
// security keys on.
const TenantColumn = "owner_id"

// ErrNoTenant is returned on PostgreSQL when an operation runs without an
// organization in the context. It fails closed rather than run unscoped.
var ErrNoTenant = errors.New("connections: no organization in context")

// Options configures [Open].
type Options struct {
	// DB is the platform database. Required.
	DB *sql.DB
	// Dialect is the database's dialect. Required.
	Dialect sqlstore.Dialect
	// Keys seals and opens credentials; it must manage [Purpose]. Required.
	Keys *keys.Keys
	// Authorizer decides who may view, use, manage, share and disconnect a
	// connection. Required.
	Authorizer authz.Authorizer
	// Vault holds deployment secrets such as OAuth client secrets and GitHub
	// App keys. Optional: without it, [Connections.Secrets] reads nothing.
	Vault vault.Vault
	// Audit receives connection events. Optional.
	Audit sfaudit.Store
	// RLS configures the session variable that carries the organization. The
	// zero value uses the platform default.
	RLS *rls.Config
}

// Connections is connectionforge composed with the platform: each field is a
// connectionforge port backed by SystemForge.
type Connections struct {
	Store      *sqlstore.Store
	Crypto     cf.Cryptographer
	Secrets    cf.SecretSource
	Authorizer cf.Authorizer
	Auditor    cf.Auditor

	db      *sql.DB
	dialect sqlstore.Dialect
	rls     *rls.Config
}

// Open composes the ports. It does not change the database: call
// [Connections.Migrate] first.
func Open(o Options) (*Connections, error) {
	switch {
	case o.DB == nil:
		return nil, errors.New("connections: Options.DB is required")
	case o.Keys == nil:
		return nil, errors.New("connections: Options.Keys is required")
	case o.Authorizer == nil:
		return nil, errors.New("connections: Options.Authorizer is required")
	}
	cfg := o.RLS
	if cfg == nil {
		cfg = rls.DefaultConfig()
	}
	var opts []sqlstore.Option
	if o.Dialect == sqlstore.Postgres {
		opts = append(opts, sqlstore.WithTxHook(tenantHook(rls.NewHelper(cfg))))
	}
	store, err := sqlstore.New(o.DB, o.Dialect, opts...)
	if err != nil {
		return nil, fmt.Errorf("connections: %w", err)
	}
	c := &Connections{
		Store:      store,
		Crypto:     cryptographer{k: o.Keys},
		Secrets:    secretSource{v: o.Vault},
		Authorizer: authorizer{az: o.Authorizer},
		Auditor:    nopAuditor{},
		db:         o.DB,
		dialect:    o.Dialect,
		rls:        cfg,
	}
	if o.Audit != nil {
		c.Auditor = auditor{store: o.Audit}
	}
	return c, nil
}

// Migrate creates or updates connectionforge's tables and, on PostgreSQL,
// enables row-level security on the owned ones, keyed on [TenantColumn]. Run
// it with a role allowed to change the schema.
func (c *Connections) Migrate(ctx context.Context) error {
	if err := c.Store.Migrate(ctx); err != nil {
		return err
	}
	if c.dialect != sqlstore.Postgres {
		return nil
	}
	m := rls.NewMigrator(c.db, &rls.MigrationConfig{
		TenantColumn:    TenantColumn,
		SessionVariable: c.rls.SessionVariable,
	})
	for _, t := range c.Store.Tables() {
		if err := m.EnableRLS(ctx, t); err != nil {
			return fmt.Errorf("connections: row-level security on %s: %w", t, err)
		}
	}
	return nil
}

// OwnerFor returns the connectionforge owner for an organization.
func OwnerFor(orgID uuid.UUID) cf.OwnerID { return cf.OwnerID(orgID.String()) }

// tenantHook sets the organization from the context for each transaction, so
// row-level security applies. With no organization it refuses.
func tenantHook(h *rls.Helper) sqlstore.TxHook {
	return func(ctx context.Context, tx *sql.Tx) error {
		if !rls.HasTenant(ctx) {
			return ErrNoTenant
		}
		return h.SetTenant(ctx, tx, rls.TenantIDString(ctx))
	}
}
