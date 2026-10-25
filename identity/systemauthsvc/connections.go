package systemauthsvc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// openConnectionKeys opens the connections key system described by cc.
// o supplies Audit, Logger and AcceptRollback; the directory, root key
// and purposes come from cc. It also returns the vault holding the root
// key, which the connections store reads credentials from.
func openConnectionKeys(ctx context.Context, cc *systemauth.ConnectionsConfig, o keys.Options) (*keys.Keys, omnivault.Vault, error) {
	if err := keys.CheckRootKeyLocation(cc.Vault, cc.RootKey, cc.KeysDir); err != nil {
		return nil, nil, fmt.Errorf("systemauthsvc: connections: %w", err)
	}
	v, err := omnivault.VaultFromURI(cc.Vault)
	if err != nil {
		return nil, nil, fmt.Errorf("systemauthsvc: connections vault: %w", err)
	}
	o.Dir = cc.KeysDir
	o.Root = keys.VaultSource(v, cc.RootKey)
	o.Purposes = []keyforge.Purpose{connections.Purpose}
	k, err := keys.Open(ctx, o)
	if err != nil {
		return nil, nil, err
	}
	return k, v, nil
}

// AcceptKeyRollback opens the connections keyring once with
// keys.Options.AcceptRollback and closes it again. Run it after restoring
// the keys directory from a backup, after moving it to a new host without
// its rollback state, or once after upgrading from a release whose
// rollback state was not authenticated. Opening it records the accepted
// generation, so later starts succeed without the option. Confirm the
// keyring is the one you mean to keep before running it: accepting an
// older keyring brings back the key versions it holds.
func AcceptKeyRollback(ctx context.Context, cfg *Config, logger *slog.Logger) error {
	if cfg == nil || cfg.Connections == nil {
		return errors.New("systemauthsvc: no connections keyring is configured")
	}
	k, _, err := openConnectionKeys(ctx, cfg.Connections, keys.Options{
		Logger:         logger,
		AcceptRollback: true,
	})
	if err != nil {
		return err
	}
	return k.Close()
}

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
	var (
		v   omnivault.Vault
		err error
	)
	s.keys, v, err = openConnectionKeys(ctx, cc, keys.Options{
		Audit:  opts.AuditStore,
		Logger: s.logger,
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
