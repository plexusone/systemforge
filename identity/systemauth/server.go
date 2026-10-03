package systemauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/plexusone/systemforge/observability"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// Server is the SystemAuth OAuth 2.0 / OpenID Connect server.
type Server struct {
	config          *Config
	storage         Storage
	sessionProvider SessionProvider
	oauth2          fosite.OAuth2Provider
	key             *rsa.PrivateKey
	huma            huma.API
	router          chi.Router
	logger          *slog.Logger
	observability   *observability.Observability
}

// Option configures a Server.
type Option func(*Server)

// WithLogger sets the logger for the server.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

// WithStorage sets a custom storage implementation.
func WithStorage(storage Storage) Option {
	return func(s *Server) {
		s.storage = storage
	}
}

// WithSessionProvider sets a custom session provider for authentication.
func WithSessionProvider(provider SessionProvider) Option {
	return func(s *Server) {
		s.sessionProvider = provider
	}
}

// WithObservability sets the observability provider for metrics and tracing.
func WithObservability(obs *observability.Observability) Option {
	return func(s *Server) {
		s.observability = obs
	}
}

// NewEmbedded creates a SystemAuth server for embedding in applications.
// This is the simplest way to add OAuth to a SystemForge application.
//
// Example:
//
//	auth, err := systemauth.NewEmbedded(systemauth.Config{
//	    Issuer: "https://myapp.example.com",
//	})
//	router.Mount("/oauth", auth.Router())
func NewEmbedded(cfg Config, opts ...Option) (*Server, error) {
	cfg.ApplyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	s := &Server{
		config:          &cfg,
		storage:         NewMemoryStorage(),
		sessionProvider: NewDefaultSessionProvider(),
		logger:          slog.Default(),
	}

	// Apply options
	for _, opt := range opts {
		opt(s)
	}

	// Generate RSA key if not provided
	key := cfg.Keys.PrivateKey
	if key == nil {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, ErrKeyGenerationFailed
		}
	}
	s.key = key

	// Set up Fosite
	if err := s.setupFosite(); err != nil {
		return nil, err
	}

	// Register static clients from config
	for _, clientCfg := range cfg.Clients {
		client, err := NewClientFromConfig(clientCfg)
		if err != nil {
			return nil, err
		}
		if err := s.storage.CreateClient(context.Background(), client); err != nil {
			return nil, err
		}
	}

	// Set up HTTP router
	s.setupRouter()

	return s, nil
}

// setupFosite configures the Fosite OAuth2 provider.
func (s *Server) setupFosite() error {
	// Generate a hash secret if not provided
	hashSecret := make([]byte, 32)
	if _, err := rand.Read(hashSecret); err != nil {
		return err
	}

	fositeConfig := &fosite.Config{
		AccessTokenLifespan:            s.config.Tokens.AccessTokenLifetime.Duration(),
		RefreshTokenLifespan:           s.config.Tokens.RefreshTokenLifetime.Duration(),
		AuthorizeCodeLifespan:          s.config.Tokens.AuthCodeLifetime.Duration(),
		IDTokenLifespan:                s.config.Tokens.IDTokenLifetime.Duration(),
		GlobalSecret:                   hashSecret,
		SendDebugMessagesToClients:     false,
		EnforcePKCE:                    s.config.Features.RequirePKCE,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
	}

	// Key getter function for JWT signing
	keyGetter := func(_ context.Context) (interface{}, error) {
		return s.key, nil
	}

	// Create JWT signer
	jwtSigner := &jwt.DefaultSigner{
		GetPrivateKey: keyGetter,
	}

	// Build OAuth2 provider with all needed components
	s.oauth2 = compose.Compose(
		fositeConfig,
		s.storage,
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2HMACStrategy(fositeConfig),
			Signer:       jwtSigner,
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
	)

	return nil
}

// setupRouter configures the HTTP router with all endpoints.
func (s *Server) setupRouter() {
	router := chi.NewRouter()

	// Add standard middleware (must be before routes)
	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(s.loggerMiddleware)
	router.Use(s.fositeInterceptor) // Intercept OAuth paths before Huma

	// Create Huma API with OpenAPI configuration
	config := huma.DefaultConfig("SystemAuth OAuth 2.0 / OpenID Connect", "1.0")
	config.Info.Description = "OAuth 2.0 Authorization Server with OpenID Connect support"
	config.Info.Contact = &huma.Contact{
		Name: "SystemForge",
		URL:  "https://github.com/plexusone/systemforge",
	}
	config.Info.License = &huma.License{
		Name: "MIT",
		URL:  "https://opensource.org/licenses/MIT",
	}
	config.Servers = []*huma.Server{
		{URL: s.config.Issuer, Description: "OAuth Server"},
	}

	humaAPI := humachi.New(router, config)
	s.huma = humaAPI
	s.router = router

	// Register endpoints
	s.registerEndpoints()
}

// loggerMiddleware injects the logger into the request context.
func (s *Server) loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), loggerKey{}, s.logger)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loggerKey is the context key for the logger.
type loggerKey struct{}

// LoggerFromContext returns the logger from context, or slog.Default() if not set.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

// registerEndpoints registers all OAuth and OIDC endpoints.
func (s *Server) registerEndpoints() {
	// Register Huma operations for OpenAPI documentation
	s.registerOpenAPIOperations()

	// Register discovery endpoints (these are handled by Huma)
	s.registerDiscoveryEndpoints()
}

// Router returns the Chi router for mounting.
func (s *Server) Router() chi.Router {
	return s.router
}

// Huma returns the Huma API for advanced configuration.
func (s *Server) Huma() huma.API {
	return s.huma
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// Logger returns the server's logger.
func (s *Server) Logger() *slog.Logger {
	return s.logger
}

// Observability returns the observability provider, or nil if not configured.
func (s *Server) Observability() *observability.Observability {
	return s.observability
}

// OAuth2Provider returns the underlying Fosite provider.
func (s *Server) OAuth2Provider() fosite.OAuth2Provider {
	return s.oauth2
}

// Storage returns the storage implementation.
func (s *Server) Storage() Storage {
	return s.storage
}

// Session creates a new OAuth session for a user.
func (s *Server) Session(subject string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:    s.config.Issuer,
			Subject:   subject,
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(s.config.Tokens.AccessTokenLifetime.Duration()),
		},
		Headers: &jwt.Headers{},
	}
}

// RegisterClient registers a new OAuth client.
func (s *Server) RegisterClient(client *Client) error {
	return s.storage.CreateClient(context.Background(), client)
}

// GetClient retrieves a client by ID.
func (s *Server) GetClient(id string) (*Client, error) {
	return s.storage.GetClientByID(context.Background(), id)
}

// Middleware returns HTTP middleware that validates access tokens.
// Use this to protect your API endpoints.
//
// Example:
//
//	router.With(auth.Middleware()).Get("/api/me", meHandler)
func (s *Server) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			logger := LoggerFromContext(ctx)

			// Extract token from Authorization header
			token := fosite.AccessTokenFromRequest(r)
			if token == "" {
				logger.Debug("missing access token", "path", r.URL.Path)
				http.Error(w, "missing access token", http.StatusUnauthorized)
				return
			}

			// Create session for introspection
			session := s.Session("")

			// Validate the token
			_, ar, err := s.oauth2.IntrospectToken(ctx, token, fosite.AccessToken, session)
			if err != nil {
				logger.Debug("invalid access token", "path", r.URL.Path, "error", err)
				http.Error(w, "invalid access token", http.StatusUnauthorized)
				return
			}

			logger.Debug("token validated",
				"client_id", ar.GetClient().GetID(),
				"subject", ar.GetSession().GetSubject(),
				"path", r.URL.Path,
			)

			// Add token info to context
			ctx = WithAccessRequest(ctx, ar)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScopes returns middleware that requires specific scopes.
func (s *Server) RequireScopes(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ar := AccessRequestFromContext(r.Context())
			if ar == nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			grantedScopes := ar.GetGrantedScopes()
			for _, scope := range scopes {
				if !grantedScopes.Has(scope) {
					http.Error(w, "insufficient scope: "+scope, http.StatusForbidden)
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// accessRequestKey is the context key for the access request.
type accessRequestKey struct{}

// WithAccessRequest adds the access request to the context.
func WithAccessRequest(ctx context.Context, ar fosite.AccessRequester) context.Context {
	return context.WithValue(ctx, accessRequestKey{}, ar)
}

// AccessRequestFromContext retrieves the access request from context.
func AccessRequestFromContext(ctx context.Context) fosite.AccessRequester {
	if ar, ok := ctx.Value(accessRequestKey{}).(fosite.AccessRequester); ok {
		return ar
	}
	return nil
}
