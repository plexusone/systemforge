package invite

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
	"github.com/plexusone/systemforge/identity/organization"
)

// APIConfig configures the Invite API.
type APIConfig struct {
	// BasePath is the base path for all endpoints (default: "/api/v1").
	BasePath string
	// Logger is the logger to use (default: slog.Default()).
	Logger *slog.Logger
	// Authorizer checks the caller's organization permissions; managing
	// an organization's invites needs authz.PermOrgInviteMember. Until it
	// is set, those endpoints answer 501.
	Authorizer authz.Authorizer
	// Caller identifies the authenticated principal (default:
	// requestprincipal.PrincipalUUID, set by requestprincipal.Middleware).
	Caller func(ctx context.Context) (uuid.UUID, error)
	// PrincipalEmail returns the caller's email, which an invite must be
	// addressed to (default: the service's PrincipalEmail, when it has
	// one, as DefaultService does).
	PrincipalEmail PrincipalEmailFunc
}

// DefaultAPIConfig returns the default API configuration.
func DefaultAPIConfig() APIConfig {
	return APIConfig{
		BasePath: "/api/v1",
		Logger:   slog.Default(),
	}
}

// API provides HTTP handlers for Invite management.
type API struct {
	huma    huma.API
	router  chi.Router
	service Service
	orgSvc  organization.Service
	config  APIConfig
}

// NewAPI creates a new Invite API.
func NewAPI(service Service, orgSvc organization.Service, config APIConfig) *API {
	if config.BasePath == "" {
		config.BasePath = "/api/v1"
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	api := &API{
		service: service,
		orgSvc:  orgSvc,
		config:  config,
	}

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(api.loggerMiddleware)

	humaConfig := huma.DefaultConfig("Invite API", "1.0")
	humaConfig.Info.Description = "Organization invitation management API"

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

// registerEndpoints registers all invite endpoints.
func (a *API) registerEndpoints() {
	a.registerInviteEndpoints()
}
