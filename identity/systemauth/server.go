package systemauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/plexusone/systemforge/identity/appcatalog"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/dpopproof"
	"github.com/plexusone/systemforge/observability"
)

// Server is the SystemAuth OAuth 2.0 / OpenID Connect server.
type Server struct {
	config          *Config
	storage         Storage
	sessionProvider SessionProvider
	oauth2          fosite.OAuth2Provider
	key             *rsa.PrivateKey
	keyID           string
	keys            *KeyRing
	codeStrategy    oauth2.AuthorizeCodeStrategy
	dpop            *dpopproof.Checker
	dpopCache       dpopproof.ReplayCache
	huma            huma.API
	router          chi.Router
	logger          *slog.Logger
	observability   *observability.Observability
	socialOpts      socialOptions
	social          *socialLogin
	readiness       []readinessCheck
	orgs            OrgsSource
	appCatalog      *appcatalog.Catalog
	accessChanges   AccessChangeLister
	accessScope     AccessChangeScope
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

	// Load the configured signing key, or generate an ephemeral one
	// (development: tokens do not survive a restart).
	if err := cfg.Keys.LoadSigningKey(); err != nil {
		return nil, err
	}
	key := cfg.Keys.PrivateKey
	if key == nil {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, ErrKeyGenerationFailed
		}
		s.logger.Warn("no signing key configured; generated an ephemeral key (tokens will not verify after a restart)")
	}
	s.key = key
	s.keyID = cfg.Keys.KeyID
	if s.keyID == "" {
		kid, err := KeyThumbprint(key)
		if err != nil {
			return nil, err
		}
		s.keyID = kid
	}
	if err := s.config.Keys.LoadVerificationKeys(s.keyID); err != nil {
		return nil, err
	}
	s.keys = newKeyRing(key, s.keyID, s.config.Keys.VerificationKeys)

	// Set up Fosite and DPoP proof checking
	if err := s.setupFosite(); err != nil {
		return nil, err
	}
	if err := s.setupDPoP(); err != nil {
		return nil, err
	}

	// Register static clients from config. With persistent storage they
	// already exist after a restart (or on a sibling replica), so existing
	// clients are updated from the config instead.
	for _, clientCfg := range cfg.Clients {
		client, err := NewClientFromConfig(clientCfg)
		if err != nil {
			return nil, err
		}
		err = s.storage.CreateClient(context.Background(), client)
		if errors.Is(err, ErrClientExists) {
			err = s.storage.UpdateClient(context.Background(), client)
		}
		if err != nil {
			return nil, err
		}
	}

	// Set up browser login: GitHub/Google social login if configured, and
	// login-token sign-in for managed principals when they are enabled.
	if loginCfg := s.browserLoginConfig(); loginCfg != nil {
		social, err := newSocialLogin(s, loginCfg)
		if err != nil {
			return nil, err
		}
		s.social = social
		s.sessionProvider = newSocialSessionProvider(s.sessionProvider, social)
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
		AccessTokenIssuer:              s.config.Issuer,
		IDTokenIssuer:                  s.config.Issuer,
		AccessTokenLifespan:            s.config.Tokens.AccessTokenLifetime.Duration(),
		RefreshTokenLifespan:           s.config.Tokens.RefreshTokenLifetime.Duration(),
		AuthorizeCodeLifespan:          s.config.Tokens.AuthCodeLifetime.Duration(),
		IDTokenLifespan:                s.config.Tokens.IDTokenLifetime.Duration(),
		GlobalSecret:                   hashSecret,
		SendDebugMessagesToClients:     false,
		EnforcePKCE:                    s.config.Features.RequirePKCE,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
		ClientSecretsHasher:            ClientSecretHasher{},
	}

	// JWTs are signed with the signing key and verified with the key their
	// kid selects from the key ring (the signing key and the verification
	// keys), so tokens signed before a rotation keep verifying.
	jwtSigner := s.keys.Signer()

	// Access tokens are opaque (HMAC) by default, or RS256 JWTs verifiable
	// against the JWKS when features.enable_jwt_access_tokens is set. Either
	// way they are also stored, so revocation and introspection work.
	var coreStrategy oauth2.CoreStrategy = compose.NewOAuth2HMACStrategy(fositeConfig)
	if s.config.Features.EnableJWTAccessTokens {
		coreStrategy = &oauth2.DefaultJWTStrategy{Signer: jwtSigner, HMACSHAStrategy: coreStrategy, Config: fositeConfig}
	}

	s.codeStrategy = coreStrategy

	// Build OAuth2 provider with all needed components
	s.oauth2 = compose.Compose(
		fositeConfig,
		s.storage,
		&compose.CommonStrategy{
			CoreStrategy:               coreStrategy,
			OpenIDConnectTokenStrategy: &openid.DefaultStrategy{Signer: jwtSigner, Config: fositeConfig},
			Signer:                     jwtSigner,
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
		// OpenID Connect: ID tokens for the code flow and on refresh.
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
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

	if s.appCatalog != nil {
		s.router.Get(appcatalog.WellKnownPath, s.handleAppCatalog)
	}

	// Liveness and readiness
	s.router.Get(HealthzPath, s.handleHealthz)
	s.router.Get(ReadyzPath, s.handleReadyz)

	// Register GitHub/Google login routes
	if s.social != nil {
		s.social.registerRoutes(s.router)
	}
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

// Session creates a new, empty OAuth session for subject. Storage
// implementations hydrate it when loading codes and tokens.
func (s *Server) Session(subject string) *Session {
	return &Session{
		DefaultSession: &openid.DefaultSession{
			Claims: &jwt.IDTokenClaims{
				Issuer:    s.config.Issuer,
				Subject:   subject,
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(s.config.Tokens.AccessTokenLifetime.Duration()),
			},
			Headers: s.jwtHeaders(),
			Subject: subject,
		},
		AccessHeader: s.accessTokenHeaders(),
	}
}

// KeyID returns the key ID ("kid") of the signing key, published in the
// JWKS and set in the header of every JWT the server signs. It is
// keys.key_id when configured, otherwise the key's RFC 7638 thumbprint.
func (s *Server) KeyID() string {
	return s.keyID
}

// jwtHeaders returns JOSE headers carrying the signing key ID.
func (s *Server) jwtHeaders() *jwt.Headers {
	return &jwt.Headers{Extra: map[string]interface{}{"kid": s.keyID}}
}

// AccessTokenType is the JOSE typ header of JWT access tokens (RFC 9068),
// which tells resource servers they are not ID tokens or other JWTs that
// SystemAuth signs with the same key.
const AccessTokenType = "at+jwt"

// accessTokenHeaders returns the JOSE headers of JWT access tokens.
func (s *Server) accessTokenHeaders() *jwt.Headers {
	h := s.jwtHeaders()
	h.Extra["typ"] = AccessTokenType
	return h
}

// RegisterClient registers a new OAuth client.
func (s *Server) RegisterClient(client *Client) error {
	if err := ValidateBackchannelLogoutURI(client.BackchannelLogoutURI); err != nil {
		return fmt.Errorf("client %q: %w", client.ID, err)
	}
	return s.storage.CreateClient(context.Background(), client)
}

// GetClient retrieves a client by ID.
func (s *Server) GetClient(id string) (*Client, error) {
	return s.storage.GetClientByID(context.Background(), id)
}

// ManagedPrincipalsAllowed reports whether clientID may create and sign in
// managed principals: the deployment must enable managed principals and the
// client must opt in. It is the single check every managed-principal path
// uses, so neither switch can be enforced without the other (ADR-005).
func (s *Server) ManagedPrincipalsAllowed(ctx context.Context, clientID string) (bool, error) {
	if s.config.ManagedPrincipals == nil || !s.config.ManagedPrincipals.Enabled {
		return false, nil
	}
	client, err := s.storage.GetClientByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			return false, nil
		}
		return false, err
	}
	return client.ManagedPrincipalsEnabled, nil
}

// managedPrincipalsEnabled reports whether the deployment allows managed
// principals at all.
func (s *Server) managedPrincipalsEnabled() bool {
	return s.config.ManagedPrincipals != nil && s.config.ManagedPrincipals.Enabled
}

// browserLoginConfig returns the configuration of browser login sessions:
// the social login configuration, or defaults when only managed
// principals need sessions. Nil means browser login is off.
func (s *Server) browserLoginConfig() *SocialLoginConfig {
	if s.config.SocialLogin != nil {
		return s.config.SocialLogin
	}
	if !s.managedPrincipalsEnabled() {
		return nil
	}
	return &SocialLoginConfig{DefaultRedirect: "/", SessionLifetime: Duration(12 * time.Hour)}
}

// LoginTokenPolicy returns the lifetime policy for login tokens issued for
// clientID's managed principals: the deployment's settings, with the
// client's own default lifetime when it sets one. Callers check
// ManagedPrincipalsAllowed first.
func (s *Server) LoginTokenPolicy(ctx context.Context, clientID string) (credential.LoginTokenPolicy, error) {
	var p credential.LoginTokenPolicy
	if mp := s.config.ManagedPrincipals; mp != nil {
		p = credential.LoginTokenPolicy{
			DefaultTTL:   mp.LoginTokenTTL.Duration(),
			MaxTTL:       mp.LoginTokenMaxTTL.Duration(),
			SingleUseTTL: mp.SingleUseTokenTTL.Duration(),
		}
	}
	client, err := s.storage.GetClientByID(ctx, clientID)
	if err != nil {
		return credential.LoginTokenPolicy{}, err
	}
	if client.LoginTokenTTL != nil {
		p.DefaultTTL = *client.LoginTokenTTL
	}
	return p, nil
}

// Middleware returns HTTP middleware that validates access tokens.
// Use this to protect your API endpoints. A DPoP-bound token is accepted
// only with the DPoP scheme and a proof by its key whose htu is the
// issuer's origin plus the request path; an unbound one only with the
// Bearer scheme.
//
// Example:
//
//	router.With(auth.Middleware()).Get("/api/me", meHandler)
func (s *Server) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			logger := LoggerFromContext(ctx)

			// Validate the token: a DPoP-bound one needs the DPoP scheme and
			// a proof by its key for this request.
			ar, authErr := s.authenticateAccessToken(r, s.requestURL(r))
			if authErr != nil {
				logger.Debug("access token refused", "path", r.URL.Path, "error", authErr)
				s.writeTokenAuthError(w, authErr)
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
