package systemauthsvc

import (
	"net/http"

	"github.com/plexusone/systemforge/identity/managedprincipal"
	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/session/ratelimit"
)

// ManagedPrincipalsPath is where SystemAuth serves the managed-principal API
// to relying parties when the configuration enables managed principals. A
// request authenticates with the manager's access token, granted
// managedprincipal.Scope.
const ManagedPrincipalsPath = "/managed-principals"

// openManagedPrincipals builds the managed-principal service and mounts its
// API when the configuration enables managed principals and the service has
// a database. Login tokens are exchanged at systemauth.LoginTokenPath, which
// the server serves on its own under the same conditions.
func (s *Service) openManagedPrincipals(c *Config, opts Options) {
	if c.ManagedPrincipals == nil || !c.ManagedPrincipals.Enabled || s.client == nil {
		return
	}
	syncer, syncMode := s.authzSyncer()
	mpOpts := []managedprincipal.Option{managedprincipal.WithLogger(s.logger), managedprincipal.WithAuthzSyncer(syncer, syncMode)}
	if opts.AuditEmitter != nil {
		mpOpts = append(mpOpts, managedprincipal.WithAuditEmitter(opts.AuditEmitter))
	}
	mpOpts = append(mpOpts, opts.ManagedPrincipalOptions...)
	s.mp = managedprincipal.NewService(s.client, s.server, mpOpts...)

	rates := opts.ManagedPrincipalRates
	if rates == nil {
		mem := ratelimit.NewMemoryStorage()
		s.mpRates = mem
		rates = mem
	}
	h := managedprincipal.NewHandler(s.mp,
		managedprincipal.WithRequestClient(managedprincipal.RequestClientFromPrincipal),
		managedprincipal.WithCodeRateLimit(rates, managedprincipal.DefaultCodeLimit),
	)
	auth := requestprincipal.Middleware(requestprincipal.Options{Logger: s.logger},
		s.server.BearerAuthenticator(managedprincipal.Scope))
	s.server.Router().Mount(ManagedPrincipalsPath, noStore(auth(h)))
	s.logger.Info("managed principals enabled", "api", ManagedPrincipalsPath)
}

// noStore marks every response of the API, including authentication
// failures, as not cacheable.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// ManagedPrincipals returns the managed-principal service, or nil when the
// configuration does not enable managed principals or there is no database.
// A host application in the same process may call it directly instead of
// the HTTP API; it then supplies the acting principal and client itself.
func (s *Service) ManagedPrincipals() *managedprincipal.Service { return s.mp }

// closeManagedPrincipals releases the rate-limit storage New created.
func (s *Service) closeManagedPrincipals() error {
	if s.mpRates == nil {
		return nil
	}
	err := s.mpRates.Close()
	s.mpRates = nil
	return err
}
