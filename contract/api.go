package contract

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// API wraps the Huma API and provides contract endpoint registration.
type API struct {
	huma     huma.API
	router   chi.Router
	provider *Provider
	logger   *slog.Logger
}

// Option configures an API.
type Option func(*API)

// WithLogger sets the logger for the API.
// If not set, slog.Default() is used.
func WithLogger(logger *slog.Logger) Option {
	return func(a *API) {
		a.logger = logger
	}
}

// NewAPI creates a new contract API with Chi router and Huma.
func NewAPI(provider *Provider, opts ...Option) (*API, error) {
	api := &API{
		provider: provider,
		logger:   slog.Default(),
	}

	// Apply options
	for _, opt := range opts {
		opt(api)
	}

	router := chi.NewRouter()

	// Add standard middleware
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(api.loggerMiddleware)

	// Create Huma API with OpenAPI configuration
	config := huma.DefaultConfig("SystemForge Contract API", provider.Config().Version)
	config.Info.Description = "SystemForge Product Contract API for SystemAuth federation integration"

	// Add contact info
	config.Info.Contact = &huma.Contact{
		Name: "SystemForge",
		URL:  "https://github.com/plexusone/systemforge",
	}

	// Add license
	config.Info.License = &huma.License{
		Name: "MIT",
		URL:  "https://opensource.org/licenses/MIT",
	}

	// Configure servers based on base URL
	baseURL := provider.Config().BaseURL
	config.Servers = []*huma.Server{
		{URL: baseURL, Description: "Contract API"},
	}

	humaAPI := humachi.New(router, config)

	api.huma = humaAPI
	api.router = router

	// Register all endpoints
	api.registerEndpoints()

	return api, nil
}

// Logger returns the API's logger.
func (a *API) Logger() *slog.Logger {
	return a.logger
}

// loggerMiddleware injects the logger into the request context.
func (a *API) loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := withLogger(r.Context(), a.logger)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loggerKey is the context key for the logger.
type loggerKey struct{}

// withLogger adds a logger to the context.
func withLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// LoggerFromContext returns the logger from context, or slog.Default() if not set.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

// Router returns the Chi router for mounting or serving.
func (a *API) Router() chi.Router {
	return a.router
}

// Huma returns the underlying Huma API for advanced configuration.
func (a *API) Huma() huma.API {
	return a.huma
}

// Provider returns the contract provider.
func (a *API) Provider() *Provider {
	return a.provider
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// registerEndpoints registers all contract endpoints with Huma.
func (a *API) registerEndpoints() {
	// Metadata endpoint (always available)
	a.registerMetaEndpoints()

	// Identity endpoints
	if a.provider.Config().HasCapability(CapabilityIdentity) {
		a.registerIdentityEndpoints()
	}

	// Policy endpoints
	if a.provider.Config().HasCapability(CapabilityRBAC) {
		a.registerPolicyEndpoints()
	}

	// Audit endpoints
	if a.provider.Config().HasCapability(CapabilityAudit) {
		a.registerAuditEndpoints()
	}

	// Health endpoints (always available)
	a.registerHealthEndpoints()
}

// checkPermission verifies the request has the required permission.
// In standalone mode, all permissions are granted.
// In federated mode, permissions come from the SystemAuth JWT.
func (a *API) checkPermission(ctx context.Context, permission string) error {
	// In standalone mode, allow all operations
	if !a.provider.FederationState().IsFederated() {
		return nil
	}

	// In federated mode, check permissions from context
	if !HasPermission(ctx, permission) {
		return huma.Error403Forbidden("missing required permission: " + permission)
	}
	return nil
}

// checkFederated verifies the application is in federation mode.
func (a *API) checkFederated() error {
	if !a.provider.FederationState().IsFederated() {
		return huma.Error503ServiceUnavailable("application is not in federation mode")
	}
	return nil
}

// startSync attempts to start a sync operation.
// Returns an error if sync is already in progress.
func (a *API) startSync() error {
	if !a.provider.FederationState().StartSync() {
		return huma.Error409Conflict("sync already in progress")
	}
	return nil
}
