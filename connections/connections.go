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
	"log/slog"

	"github.com/google/uuid"
	cf "github.com/plexusone/connectionforge"
	"github.com/plexusone/connectionforge/broker"
	"github.com/plexusone/connectionforge/egress"
	"github.com/plexusone/connectionforge/provider"
	"github.com/plexusone/connectionforge/service"
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
	// Audit receives connection events. Optional: without it, and with a
	// Logger, events are logged.
	Audit sfaudit.Store
	// Logger receives connection events when there is no audit store.
	Logger *slog.Logger
	// RLS configures the session variable that carries the organization. The
	// zero value uses the platform default.
	RLS *rls.Config
	// Providers are the providers applications registered. The zero value is
	// an empty registry.
	Providers *provider.Registry
	// Egress is the outbound policy template. The zero value allows only
	// HTTPS to each provider's public hosts; development may allow more.
	Egress egress.Policy
}

// Connections is connectionforge composed with the platform: each field is a
// connectionforge port backed by SystemForge.
type Connections struct {
	Store      *sqlstore.Store
	Crypto     cf.Cryptographer
	Secrets    cf.SecretSource
	Authorizer cf.Authorizer
	Auditor    cf.Auditor
	Providers  *provider.Registry
	// Broker hands out authenticated HTTP clients for a connection.
	Broker *broker.Broker
	// Service runs create, get, list, rename, test and disconnect.
	Service *service.Service

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
	switch {
	case o.Audit != nil:
		c.Auditor = auditor{store: o.Audit}
	case o.Logger != nil:
		c.Auditor = LogAuditor(o.Logger)
	}
	c.Providers = o.Providers
	if c.Providers == nil {
		c.Providers = provider.NewRegistry()
	}
	c.Broker, err = broker.New(broker.Options{
		Store: store, Crypto: c.Crypto, Providers: c.Providers,
		Authorizer: c.Authorizer, Auditor: c.Auditor, Egress: o.Egress,
	})
	if err != nil {
		return nil, fmt.Errorf("connections: %w", err)
	}
	c.Service, err = service.New(service.Options{
		Store: store, Broker: c.Broker, Providers: c.Providers,
		Authorizer: c.Authorizer, Auditor: c.Auditor,
	})
	if err != nil {
		return nil, fmt.Errorf("connections: %w", err)
	}
	return c, nil
}

// Migrate creates or updates connectionforge's tables and, on PostgreSQL,
// enables row-level security on the owned ones. See [MigrateSchema].
func (c *Connections) Migrate(ctx context.Context) error {
	return MigrateSchema(ctx, c.db, c.dialect, c.rls)
}

// MigrateSchema creates or updates connectionforge's tables and, on
// PostgreSQL, enables row-level security on the owned ones, keyed on
// [TenantColumn]. It needs no keys, so a migration command can run it alone.
// Run it with a role allowed to change the schema. A nil cfg uses the
// platform default session variable.
func MigrateSchema(ctx context.Context, db *sql.DB, d sqlstore.Dialect, cfg *rls.Config) error {
	store, err := sqlstore.New(db, d)
	if err != nil {
		return fmt.Errorf("connections: %w", err)
	}
	if err := store.Migrate(ctx); err != nil {
		return err
	}
	if d != sqlstore.Postgres {
		return nil
	}
	if cfg == nil {
		cfg = rls.DefaultConfig()
	}
	m := rls.NewMigrator(db, &rls.MigrationConfig{
		TenantColumn:    TenantColumn,
		SessionVariable: cfg.SessionVariable,
	})
	for _, t := range store.Tables() {
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
