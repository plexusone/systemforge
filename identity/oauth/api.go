package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/systemauth"
)

// API provides HTTP handlers for OAuth 2.0 endpoints using Huma/Chi.
// It uses a hybrid approach: discovery endpoints use Huma for full typed handling,
// while Fosite-integrated endpoints use Chi handlers directly.
type API struct {
	huma     huma.API
	router   chi.Router
	provider *Provider
	logger   *slog.Logger

	authenticate func(r *http.Request) string
	loginURL     string
	consent      ConsentFunc

	// acceptedClients are the clients whose access tokens Middleware
	// accepts; anyClient accepts every client. Middleware panics when
	// neither was configured.
	acceptedClients []string
	anyClient       bool

	// resourceBaseURL is the external base URL of routes behind
	// Middleware; empty uses the issuer's origin.
	resourceBaseURL string
}

// WithResourceBaseURL sets the external base URL of the routes behind
// Middleware, such as "https://api.example.com" or, behind a proxy that
// strips a path prefix, "https://example.com/api". A DPoP proof's htu must
// equal it plus the request path as this server sees it. Default: the
// issuer's origin (scheme and host). Forwarded headers are never trusted.
func WithResourceBaseURL(baseURL string) Option {
	return func(a *API) {
		a.resourceBaseURL = strings.TrimSuffix(baseURL, "/")
	}
}

// WithAcceptedClientIDs sets the OAuth clients whose access tokens
// Middleware accepts. A token issued to any other client is refused, so a
// client a user authorized for one purpose cannot call APIs meant for
// another.
func WithAcceptedClientIDs(clientIDs ...string) Option {
	return func(a *API) {
		a.acceptedClients = append(a.acceptedClients, clientIDs...)
	}
}

// WithAnyClient makes Middleware accept access tokens issued to any active
// client of this server. Use it only when every client may call the
// protected API and scopes alone limit what each may do.
func WithAnyClient() Option {
	return func(a *API) {
		a.anyClient = true
	}
}

// ConsentFunc reports whether userID has consented to client receiving
// scopes. It is consulted for clients that are not first-party.
type ConsentFunc func(ctx context.Context, userID string, client fosite.Client, scopes []string) (bool, error)

// Option configures an API.
type Option func(*API)

// WithLogger sets the logger for the API.
// If not set, slog.Default() is used.
func WithLogger(logger *slog.Logger) Option {
	return func(a *API) {
		a.logger = logger
	}
}

// WithUserAuthenticator sets how the authorization endpoint learns who the
// user is: it returns the authenticated user's ID for the request, or ""
// when there is none, for example by validating a session cookie. Until
// one is set, the authorization endpoint refuses every request with
// server_error rather than guess.
func WithUserAuthenticator(authenticate func(r *http.Request) string) Option {
	return func(a *API) {
		a.authenticate = authenticate
	}
}

// WithTrustedUserIDHeader authenticates users from a header written by a
// gateway that has already authenticated them (a backend-for-frontend).
// Only requests the gate admits are believed; see
// systemauth.TrustedProxyNetworks and systemauth.TrustAllRequests. A nil
// gate or an empty header trusts nothing.
func WithTrustedUserIDHeader(header string, gate systemauth.RequestGate) Option {
	return WithUserAuthenticator(func(r *http.Request) string {
		if header == "" || gate == nil || !gate(r) {
			return ""
		}
		return strings.TrimSpace(r.Header.Get(header))
	})
}

// WithLoginURL sets where unauthenticated users are sent; the original
// authorization request is passed back in the redirect query parameter.
// Without it, an unauthenticated authorization request is answered with
// login_required.
func WithLoginURL(loginURL string) Option {
	return func(a *API) {
		a.loginURL = loginURL
	}
}

// WithConsent sets how consent is checked for clients that are not
// first-party. Without it such clients are refused with access_denied;
// first-party clients never need consent.
func WithConsent(consent ConsentFunc) Option {
	return func(a *API) {
		a.consent = consent
	}
}

// NewAPI creates a new OAuth API with Chi router and Huma.
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
	// Delegates the OAuth endpoints to Fosite before Huma's handlers.
	router.Use(api.fositeInterceptor)

	// Create Huma API with OpenAPI configuration
	config := huma.DefaultConfig("OAuth 2.0 / OpenID Connect API", "1.0")
	config.Info.Description = "OAuth 2.0 Authorization Server with OpenID Connect support"

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

	// Configure servers based on issuer
	config.Servers = []*huma.Server{
		{URL: provider.config.Issuer, Description: "OAuth API"},
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

// Provider returns the OAuth provider.
func (a *API) Provider() *Provider {
	return a.provider
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.router.ServeHTTP(w, r)
}

// registerEndpoints registers all OAuth endpoints.
func (a *API) registerEndpoints() {
	// Discovery endpoints via Huma (typed handlers)
	a.registerDiscoveryEndpoints()

	// Fosite endpoints via Chi (raw handlers for Fosite integration)
	a.registerFositeEndpoints()
}

// errTokenRefused is returned by acceptToken for a valid token that
// Middleware does not accept.
var errTokenRefused = errors.New("oauth: access token refused")

// acceptToken applies Middleware's checks beyond the token's own validity:
// the issuing client is accepted and active, and the principal is active.
// Storage errors refuse the token as well.
func (a *API) acceptToken(ctx context.Context, ar fosite.AccessRequester) error {
	clientID := ar.GetClient().GetID()
	if !a.anyClient && !slices.Contains(a.acceptedClients, clientID) {
		return fmt.Errorf("%w: issued to client %q", errTokenRefused, clientID)
	}
	// GetClient finds active clients only.
	if _, err := a.provider.storage.GetClient(ctx, clientID); err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			return fmt.Errorf("%w: client %q is not active", errTokenRefused, clientID)
		}
		LoggerFromContext(ctx).Error("checking client", "client_id", clientID, "error", err)
		return err
	}
	active, err := a.provider.storage.grants.PrincipalActive(ctx, ar.GetSession().GetSubject())
	if err != nil {
		LoggerFromContext(ctx).Error("checking principal", "error", err)
		return err
	}
	if !active {
		return fmt.Errorf("%w: principal is not active", errTokenRefused)
	}
	return nil
}

// Middleware provides OAuth token validation middleware. It accepts an
// access token only when it is valid and unrevoked, was issued to a client
// accepted by WithAcceptedClientIDs (or WithAnyClient) that is still
// active, and its principal is still active, the same principal check the
// introspection endpoint applies.
//
// A DPoP-bound token (RFC 9449) is accepted only with the DPoP
// authorization scheme and a fresh, unreplayed proof by its key for the
// request's method and URL, carrying the token's hash; the URL is
// WithResourceBaseURL (default: the issuer's origin) plus the request
// path. An unbound token, which only a client registered with the
// allow_bearer_tokens exception gets, is accepted only with the Bearer
// scheme. Refusals carry WWW-Authenticate challenges.
//
// Middleware panics when the API was created with neither
// WithAcceptedClientIDs nor WithAnyClient.
func (a *API) Middleware(next http.Handler) http.Handler {
	if len(a.acceptedClients) == 0 && !a.anyClient {
		panic("oauth: Middleware needs WithAcceptedClientIDs or WithAnyClient")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := LoggerFromContext(ctx)

		ar, authErr := systemauth.AuthenticateAccessToken(r, a.provider.dpop, a.resourceURL(r), func(ctx context.Context, token string) (fosite.AccessRequester, error) {
			ar, err := a.provider.introspect(ctx, token)
			if err != nil {
				return nil, err
			}
			if err := a.acceptToken(ctx, ar); err != nil {
				return nil, err
			}
			return ar, nil
		})
		if authErr != nil {
			logger.Debug("access token refused", "path", r.URL.Path, "error", authErr)
			systemauth.WriteTokenAuthError(w, authErr)
			return
		}

		logger.Debug("token validated", "client_id", ar.GetClient().GetID(), "path", r.URL.Path)

		// Add token info to context
		ctx = WithAccessRequest(ctx, ar)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resourceURL is the htu a proof for a request to a protected route must
// name: the resource base URL and the request path.
func (a *API) resourceURL(r *http.Request) string {
	base := a.resourceBaseURL
	if base == "" {
		base = a.provider.issuerOrigin()
	}
	return base + r.URL.Path
}
