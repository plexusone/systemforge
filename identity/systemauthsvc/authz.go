package systemauthsvc

import (
	"context"
	"fmt"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/mode"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/connections"
)

// openAuthz builds the authorization mode the configuration selects
// (authz.mode: rbac, the default, or rebac with SpiceDB) once, for every
// part of the service: the identity services it constructs write their
// relationships through its syncer, connections and the SCIM token API
// check with its provider, and RunJobs runs its graph reconciler. It needs
// a database; without one nothing is built and nothing is synced.
func (s *Service) openAuthz(ctx context.Context, c *Config, opts Options) error {
	if s.client == nil {
		return nil
	}
	deps := mode.Deps{
		DB:       s.client,
		Registry: opts.Vocabularies,
		SyncMode: opts.AuthzSyncMode,
		Logger:   s.logger,
		// Platform administrators are read from the database in mode rbac,
		// where IsPlatformAdmin answers the SCIM token API's check. They
		// get no bypass of other checks, such as those on connections.
		PlatformAdmin: s.isPlatformAdmin,
		RBACOptions:   []rbac.Option{rbac.WithPlatformAdminBypass(false)},
	}
	if c.Connections != nil {
		if c.Authz.Mode != "" && c.Authz.Mode != authz.ModeRBAC {
			return fmt.Errorf("systemauthsvc: connections support authz mode %q only, not %q", authz.ModeRBAC, c.Authz.Mode)
		}
		// Grants on a connection are accepted when the deployment restricts
		// them to registered applications' resource types, so register ours
		// before the mode reads the registry.
		if err := connections.RegisterVocabulary(opts.Vocabularies); err != nil {
			return fmt.Errorf("systemauthsvc: connections vocabulary: %w", err)
		}
		deps.RBACOptions = append(deps.RBACOptions, rbac.WithPermissions(connections.RolePermissions(authz.DefaultRolePermissions)))
	}
	res, err := mode.New(ctx, c.Authz, deps)
	if err != nil {
		return fmt.Errorf("systemauthsvc: authorization: %w", err)
	}
	s.authz = res
	attrs := []any{"mode", res.Mode, "graph_reconciler", res.Reconciler != nil}
	if c.Authz.SpiceDB != nil {
		attrs = append(attrs, "spicedb", c.Authz.SpiceDB.Mode)
	}
	s.logger.Info("authorization configured", attrs...)
	return nil
}

// authzSyncer returns the syncer of the authorization mode, or the no-op
// syncer without a database.
func (s *Service) authzSyncer() (authz.RelationshipSyncer, authz.SyncMode) {
	if s.authz == nil {
		return noop.NewSyncer(), authz.SyncModeEventual
	}
	return s.authz.Syncer, s.authz.SyncMode
}

// Authz returns the authorization mode the service built: its provider
// answers authorization checks, its Syncer is what identity services
// constructed beside the service should be given (with its SyncMode), and
// its Reconciler, in mode rebac, repairs the graph (run by RunJobs). It is
// nil without a database.
func (s *Service) Authz() *mode.Result { return s.authz }

// closeAuthz releases the authorization mode, stopping an embedded SpiceDB.
func (s *Service) closeAuthz() error {
	if s.authz == nil {
		return nil
	}
	r := s.authz
	s.authz = nil
	return r.Close()
}
