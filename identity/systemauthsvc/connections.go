package systemauthsvc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/plexusone/connectforge/egress"
	"github.com/plexusone/connectforge/sqlstore"
	"github.com/plexusone/keyforge"
	"github.com/plexusone/omnivault"

	"github.com/plexusone/systemforge/authz/mode"
	"github.com/plexusone/systemforge/connections"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/keys"
)

// openConnections opens the key system and the connections store when the
// configuration enables connections (ADR-017), checking with the
// service's authorization mode (openAuthz), which must be rbac.
func (s *Service) openConnections(ctx context.Context, c *Config, opts Options) error {
	cc := c.Connections
	if cc == nil {
		return nil
	}
	if s.client == nil || s.db == nil || s.authz == nil {
		return errors.New("systemauthsvc: connections need a database with a connection pool")
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
		Audit:    opts.AuditStore,
		Logger:   s.logger,
	})
	if err != nil {
		return err
	}
	s.conns, err = connections.Open(connections.Options{
		DB:         s.db,
		Dialect:    sqlstore.Dialect(s.dialect),
		Keys:       s.keys,
		Authorizer: s.authz.Provider,
		Grants:     s.authz.Provider,
		Vault:      v,
		Audit:      opts.AuditStore,
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

// RunJobs runs background work until ctx is cancelled: the key lifecycle
// jobs when connections are enabled, and, when the authorization mode is
// rebac, the authorization graph reconciler at startup and on its
// configured schedule (authz.reconcile). Run it beside the server for as
// long as the service serves. It returns at once when there is none, and
// the jobs' errors joined when they end.
func (s *Service) RunJobs(ctx context.Context) error {
	var jobs []func(context.Context) error
	if s.keys != nil {
		jobs = append(jobs, s.keys.Run)
	}
	if s.authz != nil && s.authz.Reconciler != nil {
		jobs = append(jobs, s.authz.RunReconciler)
	}
	errs := make([]error, len(jobs))
	var wg sync.WaitGroup
	for i, job := range jobs {
		wg.Go(func() { errs[i] = job(ctx) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

// AuthzReconciler returns the authorization graph reconciler, for an
// on-demand Reconcile, or nil when the authorization mode built by the
// service has no graph.
func (s *Service) AuthzReconciler() *mode.Reconciler {
	if s.authz == nil {
		return nil
	}
	return s.authz.Reconciler
}

// closeConnections releases what openConnections opened.
func (s *Service) closeConnections() error {
	var err error
	if s.keys != nil {
		err = s.keys.Close()
		s.keys = nil
	}
	s.conns = nil
	return err
}
