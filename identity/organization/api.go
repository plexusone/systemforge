package organization

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
)

// APIConfig configures the Organization API.
type APIConfig struct {
	// BasePath is the base path for all endpoints (default: "/api/v1").
	BasePath string
	// Logger is the logger to use (default: slog.Default()).
	Logger *slog.Logger
	// Authorizer checks the caller's organization permissions
	// (authz.PermOrgView, PermOrgSettings, PermOrgInviteMember, and so
	// on). Until it is set, every endpoint except creating an
	// organization and checking a slug answers 501.
	Authorizer authz.Authorizer
	// Caller identifies the authenticated principal (default:
	// requestprincipal.PrincipalUUID, set by requestprincipal.Middleware).
	Caller func(ctx context.Context) (uuid.UUID, error)
}

// DefaultAPIConfig returns the default API configuration.
func DefaultAPIConfig() APIConfig {
	return APIConfig{
		BasePath: "/api/v1",
		Logger:   slog.Default(),
	}
}

// API provides HTTP handlers for Organization management.
type API struct {
	huma    huma.API
	router  chi.Router
	service Service
	config  APIConfig
}

// NewAPI creates a new Organization API.
func NewAPI(service Service, config APIConfig) *API {
	if config.BasePath == "" {
		config.BasePath = "/api/v1"
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	api := &API{
		service: service,
		config:  config,
	}

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(api.loggerMiddleware)

	humaConfig := huma.DefaultConfig("Organization API", "1.0")
	humaConfig.Info.Description = "Organization and membership management API"

	humaAPI := humachi.New(router, humaConfig)

	api.huma = humaAPI
	api.router = router

	api.registerEndpoints()

	return api
}

// Router returns the Chi router.
func (a *API) Router() chi.Router {
	return a.router
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// loggerMiddleware injects the logger into the request context.
func (a *API) loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), loggerKey{}, a.config.Logger)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type loggerKey struct{}

// registerEndpoints registers all organization endpoints.
func (a *API) registerEndpoints() {
	a.registerOrgEndpoints()
	a.registerMemberEndpoints()
}
