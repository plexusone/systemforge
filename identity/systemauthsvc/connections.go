package systemauthsvc

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/plexusone/connectforge/egress"
	"github.com/plexusone/connectforge/sqlstore"
	"github.com/plexusone/keyforge"
	"github.com/plexusone/omnivault"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/mode"
	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/connections"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/keys"
)

// openConnections opens the key system, the authorization provider and the
// connections store when the configuration enables connections (ADR-017).
func (s *Service) openConnections(ctx context.Context, c *Config, opts Options) error {
	cc := c.Connections
	if cc == nil {
		return nil
	}
	if s.client == nil || s.db == nil {
		return errors.New("systemauthsvc: connections need a database with a connection pool")
	}
	if c.Authz.Mode != authz.ModeRBAC {
		return fmt.Errorf("systemauthsvc: connections support authz mode %q only, not %q", authz.ModeRBAC, c.Authz.Mode)
	}
	if err := keys.CheckRootKeyLocation(cc.Vault, cc.RootKey, cc.KeysDir); err != nil {
		return fmt.Errorf("systemauthsvc: connections: %w", err)
	}
	v, err := omnivault.VaultFromURI(cc.Vault)
	if err != nil {
		return fmt.Errorf("systemauthsvc: connections vault: %w", err)
	}
	s.keys, err = keys.Open(ctx, keys.Options{
		Dir:      cc.KeysDir,
		Root:     keys.VaultSource(v, cc.RootKey),
		Purposes: []keyforge.Purpose{connections.Purpose},
	})
	if err != nil {
		return err
	}
	// Grants on a connection are accepted when the deployment restricts them
	// to registered applications' resource types, so register ours.
	if err := connections.RegisterVocabulary(opts.Vocabularies); err != nil {
		return fmt.Errorf("systemauthsvc: connections vocabulary: %w", err)
	}
	s.authz, err = mode.New(ctx, c.Authz, mode.Deps{
		DB:       s.client,
		Registry: opts.Vocabularies,
		Logger:   s.logger,
		RBACOptions: []rbac.Option{
			rbac.WithPermissions(connections.RolePermissions(authz.DefaultRolePermissions)),
		},
	})
	if err != nil {
		return fmt.Errorf("systemauthsvc: connections authorization: %w", err)
	}
	s.conns, err = connections.Open(connections.Options{
		DB:         s.db,
		Dialect:    sqlstore.Dialect(s.dialect),
		Keys:       s.keys,
		Authorizer: s.authz.Provider,
		Grants:     s.authz.Provider,
		Vault:      v,
		Logger:     s.logger,
		Providers:  opts.Providers,
		Egress:     egress.Policy{AllowPrivate: cc.AllowPrivateEgress, AllowHTTP: cc.AllowPrivateEgress},
	})
	if err != nil {
		return err
	}
	s.logger.Info("connections enabled", "keys_dir", cc.KeysDir, "providers", len(s.conns.Providers.Manifests()))
	return nil
}

// mountConnections serves the connections API on the server's router.
func (s *Service) mountConnections() {
	if s.conns == nil {
		return
	}
	auth := func(r *http.Request, scope string) (uuid.UUID, error) { return s.server.BearerPrincipal(r, scope) }
	h := s.conns.Handler(auth, systemauth.WriteBearerError, s.logger)
	router := s.server.Router()
	router.Handle(connections.ProvidersPath, h)
	router.Handle(connections.ConnectionsPath, h)
	router.Handle(connections.ConnectionsPath+"/*", h)
}

// Connections returns the connections of organizations to external services,
// or nil when the configuration does not enable them. An application in the
// same process uses its Broker for authenticated clients and registers its
// providers through Options.Providers.
func (s *Service) Connections() *connections.Connections { return s.conns }

// RunJobs runs background work, the key lifecycle jobs when connections are
// enabled, until ctx is cancelled. It returns at once when there is none.
func (s *Service) RunJobs(ctx context.Context) error {
	if s.keys == nil {
		return nil
	}
	return s.keys.Run(ctx)
}

// closeConnections releases what openConnections opened.
func (s *Service) closeConnections() error {
	var errs []error
	if s.authz != nil {
		errs = append(errs, s.authz.Close())
		s.authz = nil
	}
	if s.keys != nil {
		errs = append(errs, s.keys.Close())
		s.keys = nil
	}
	s.conns = nil
	return errors.Join(errs...)
}
