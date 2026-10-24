package scim

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// API provides HTTP handlers for SCIM 2.0 endpoints using Huma/Chi.
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

// NewAPI creates a new SCIM API with Chi router and Huma.
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
	config := huma.DefaultConfig("SCIM 2.0 API", "2.0")
	config.Info.Description = "System for Cross-domain Identity Management (SCIM) 2.0 API (RFC 7643/7644)"

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
		{URL: baseURL, Description: "SCIM API"},
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

// Provider returns the SCIM provider.
func (a *API) Provider() *Provider {
	return a.provider
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// registerEndpoints registers all SCIM endpoints with Huma.
func (a *API) registerEndpoints() {
	// Discovery endpoints
	a.registerConfigEndpoints()

	// Resource endpoints
	a.registerUserEndpoints()
	a.registerGroupEndpoints()
	a.registerMeEndpoints()
	a.registerBulkEndpoints()
}

// Credential is an authenticated SCIM client.
type Credential struct {
	// Subject identifies the client (for example a token ID).
	Subject string
	// Scopes are the client's SCIM scopes (ScopeUsersRead, ...).
	Scopes []string
	// Scope is what the client may provision: its organization, or the
	// platform for an operator credential. Requests with an invalid scope
	// are refused.
	Scope Scope
}

// CredentialMiddleware returns HTTP middleware for SCIM authentication.
// authFn validates the request and returns its credential, which must be
// bound to one organization or, for platform operators, to the platform.
func (a *API) CredentialMiddleware(authFn func(r *http.Request) (Credential, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cred, err := authFn(r)
			if err != nil {
				writeHumaError(w, http.StatusUnauthorized, err.Error())
				return
			}
			if !cred.Scope.Valid() {
				writeHumaError(w, http.StatusForbidden, "SCIM credential is not bound to an organization")
				return
			}
			ctx := WithAuthSubject(r.Context(), cred.Subject)
			ctx = WithAuthScopes(ctx, cred.Scopes)
			ctx = WithScope(ctx, cred.Scope)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Middleware returns HTTP middleware for SCIM authentication.
// The authFn should validate the request and return the subject and scopes.
//
// Deprecated: Middleware binds no provisioning scope, so stores refuse its
// requests. Use CredentialMiddleware.
func (a *API) Middleware(authFn func(r *http.Request) (subject string, scopes []string, err error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject, scopes, err := authFn(r)
			if err != nil {
				writeHumaError(w, http.StatusUnauthorized, err.Error())
				return
			}

			ctx := WithAuthSubject(r.Context(), subject)
			ctx = WithAuthScopes(ctx, scopes)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// writeHumaError writes a SCIM-formatted error response.
func writeHumaError(w http.ResponseWriter, status int, detail string) {
	WriteError(w, NewError(status, "", detail))
}
