// Package mode builds the authorization provider a deployment configured
// (ADR-008): role-based ("rbac") or relationship-based ("rebac") with an
// engine, from an authz.ModeConfig.
//
// It is a separate package from authz because both providers import authz,
// and so that loading a configuration file links neither provider. An
// application reads the `authz` key of its SystemAuth configuration and
// builds the provider once:
//
//	res, err := mode.New(ctx, cfg.Authz, mode.Deps{DB: db, Registry: registry})
//	if err != nil { ... }
//	defer res.Close()
//	orgs := organization.NewService(db, organization.WithAuthzSyncer(res.Syncer))
//	invites := invite.NewService(db, baseURL, invite.WithAuthzSyncer(res.Syncer), invite.WithResourceGrants(res.Grants))
//
// Both modes implement the same platform contract (organization roles,
// application roles, resource grants, ListResources) with the same
// semantics, so switching modes is a configuration change; the membership,
// role and grant tables remain the record in both.
package mode

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/authz/rebac/spicedb"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/resourcegrant"
)

// Deps are the collaborators a mode needs.
type Deps struct {
	// DB is the identity database: the membership and grant tables both
	// modes keep. Required.
	DB *ent.Client

	// Registry holds the application vocabularies. It restricts grants to
	// registered applications' resource types and, in mode rebac, supplies
	// the schema fragments composed into the engine's schema. Optional.
	Registry *authz.VocabularyRegistry

	// SyncMode decides what a failed write to the relationship engine
	// does: authz.SyncModeStrict returns it, SyncModeEventual (the default)
	// logs it. Mode rbac writes nothing. Nothing retries a failed write, so
	// under rebac a failed revocation leaves the access in the graph; see
	// authz.SyncMode.
	SyncMode authz.SyncMode

	// AccessChangeSink announces the access changes grants record
	// (ADR-010). Optional.
	AccessChangeSink accesschange.Sink

	// Logger records sync failures and startup. Default: slog.Default().
	Logger *slog.Logger

	// PlatformAdmin and ManagerRoles feed the role-based provider's
	// platform-admin bypass and manager-role checks (rbac.WithPlatformAdminChecker and rbac.WithManagerRoleGetter). Mode rebac reads
	// both from the graph. Optional.
	PlatformAdmin func(ctx context.Context, principalID uuid.UUID) (bool, error)
	ManagerRoles  authz.ManagerRoleGetter

	// RBACOptions are further options for the role-based provider, such as
	// WithPermissions and WithRoleHierarchy. They apply after the ones
	// above.
	RBACOptions []rbac.Option
}

// Result is a configured mode.
type Result struct {
	// Mode is the configured mode.
	Mode authz.Mode

	// Provider answers authorization checks and implements the resource
	// grant contract. For mode rbac it is a *rbac.Provider, which also
	// implements authz.DecisionAuthorizer; for rebac, a *spicedb.Provider.
	Provider authz.Provider

	// Syncer is the relationship syncer to pass to the identity services
	// (organization, invite, approle: their WithAuthzSyncer options). Mode
	// rbac returns the no-op syncer, since it reads the tables at check
	// time; mode rebac returns the engine's, which also implements
	// authz.AppRoleSyncer and authz.ResourceGrantSyncer.
	Syncer authz.RelationshipSyncer

	// Grants is the resource-grant store both modes keep, for services that
	// grant inside their own transactions (invite.WithResourceGrants).
	Grants *resourcegrant.Service

	closeFn func() error
}

// Close releases what the mode holds: the engine's connection, and, for an
// embedded SpiceDB, the instance. It is safe to call on any Result.
func (r *Result) Close() error {
	if r == nil || r.closeFn == nil {
		return nil
	}
	return r.closeFn()
}

// New builds the provider cfg selects. It applies the configuration's
// defaults and validates it, so a zero authz.ModeConfig is mode rbac.
//
// For mode rebac with an embedded engine it starts the instance and writes
// the composed schema; with a remote engine it connects, and writes the
// schema only when the configuration says so (authz.SpiceDBConfig.
// WriteSchema).
func New(ctx context.Context, cfg authz.ModeConfig, deps Deps) (*Result, error) {
	if deps.DB == nil {
		return nil, errors.New("authz/mode: Deps.DB is required")
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	switch cfg.Mode {
	case authz.ModeRBAC:
		return newRBAC(deps), nil
	case authz.ModeReBAC:
		switch cfg.Engine {
		case authz.EngineSpiceDB:
			return newSpiceDB(ctx, cfg, deps)
		default:
			return nil, fmt.Errorf("authz/mode: engine %q is not implemented", cfg.Engine)
		}
	}
	return nil, fmt.Errorf("authz/mode: unknown mode %q", cfg.Mode)
}

func (d Deps) storeOptions(syncer authz.RelationshipSyncer) []resourcegrant.Option {
	opts := []resourcegrant.Option{resourcegrant.WithLogger(d.Logger)}
	if d.Registry != nil {
		opts = append(opts, resourcegrant.WithVocabularies(d.Registry))
	}
	if d.AccessChangeSink != nil {
		opts = append(opts, resourcegrant.WithAccessChangeSink(d.AccessChangeSink))
	}
	if syncer != nil {
		mode := d.SyncMode
		if mode == "" {
			mode = authz.SyncModeEventual
		}
		opts = append(opts, resourcegrant.WithAuthzSyncer(syncer, mode))
	}
	return opts
}

func newRBAC(deps Deps) *Result {
	store := resourcegrant.NewService(deps.DB, deps.storeOptions(nil)...)
	opts := []rbac.Option{
		rbac.WithRoleGetter(organization.MembershipRoleGetter(organization.NewService(deps.DB))),
		rbac.WithResourceGrants(store),
	}
	if deps.PlatformAdmin != nil {
		opts = append(opts, rbac.WithPlatformAdminChecker(deps.PlatformAdmin))
	}
	if deps.ManagerRoles != nil {
		opts = append(opts, rbac.WithManagerRoleGetter(deps.ManagerRoles))
	}
	opts = append(opts, deps.RBACOptions...)
	return &Result{
		Mode:     authz.ModeRBAC,
		Provider: rbac.New(opts...),
		Syncer:   noop.NewSyncer(),
		Grants:   store,
	}
}

func newSpiceDB(ctx context.Context, cfg authz.ModeConfig, deps Deps) (*Result, error) {
	client, err := spicedb.NewClient(ctx, *cfg.SpiceDB, deps.Logger)
	if err != nil {
		return nil, fmt.Errorf("authz/mode: starting spicedb: %w", err)
	}
	fail := func(err error) (*Result, error) {
		return nil, errors.Join(err, client.Close())
	}

	if client.IsEmbedded() || cfg.SpiceDB.WriteSchema {
		schema := authz.BaseSpiceDBSchema
		if deps.Registry != nil {
			if schema, err = deps.Registry.ComposeSpiceDBSchema(); err != nil {
				return fail(fmt.Errorf("authz/mode: composing schema: %w", err))
			}
		}
		if err = client.WriteSchema(ctx, schema); err != nil {
			return fail(fmt.Errorf("authz/mode: writing schema: %w", err))
		}
	}

	syncer := spicedb.NewSyncer(client)
	store := resourcegrant.NewService(deps.DB, deps.storeOptions(syncer)...)
	return &Result{
		Mode:     authz.ModeReBAC,
		Provider: spicedb.NewProvider(client, spicedb.WithResourceGrants(store)),
		Syncer:   syncer,
		Grants:   store,
		closeFn:  client.Close,
	}, nil
}
