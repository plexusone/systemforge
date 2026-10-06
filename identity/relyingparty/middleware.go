package relyingparty

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/plexusone/systemforge/identity/apikey"
)

// AuthMethod is how a request was authenticated.
type AuthMethod string

const (
	// AuthMethodSession is a BFF cookie session.
	AuthMethodSession AuthMethod = "session"
	// AuthMethodAccessToken is a SystemAuth JWT access token.
	AuthMethodAccessToken AuthMethod = "access_token"
	// AuthMethodAPIKey is an API key.
	AuthMethodAPIKey AuthMethod = "api_key"
)

// AuthenticatedPrincipal is the principal of an authenticated request.
type AuthenticatedPrincipal struct {
	// ID is the app-local principal ID (for a client-credentials token
	// without a local principal, the OAuth client ID).
	ID string
	// Type is the principal type: human, service, ... or "client" for a
	// client-credentials token.
	Type string
	// Subject is the SystemAuth subject (sf_principal_id), when known.
	Subject string
	// Method is how the request authenticated.
	Method AuthMethod
	// Scopes are the token or API key scopes (empty for sessions, which
	// carry the principal's full access).
	Scopes []string
	// Memberships are the principal's organization memberships. For an
	// organization-scoped API key, only that organization's membership.
	Memberships []Membership
	// APIKeyID is the API key ID for AuthMethodAPIKey.
	APIKeyID string
}

// HasScope reports whether the principal's credential carries scope.
// Session principals have no scopes and always return false.
func (p *AuthenticatedPrincipal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

type principalKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p *AuthenticatedPrincipal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext returns the authenticated principal, if any.
func PrincipalFromContext(ctx context.Context) (*AuthenticatedPrincipal, bool) {
	p, ok := ctx.Value(principalKey{}).(*AuthenticatedPrincipal)
	return p, ok && p != nil
}

// AccessTokenVerifier verifies JWT access tokens. *Client implements it.
type AccessTokenVerifier interface {
	VerifyAccessToken(ctx context.Context, raw string) (*AccessTokenClaims, error)
}

// APIKeyValidator validates API keys. *apikey.Service implements it.
type APIKeyValidator interface {
	Validate(ctx context.Context, key string) (*apikey.APIKey, error)
}

// BearerConfig configures BearerMiddleware.
type BearerConfig struct {
	// Tokens verifies SystemAuth JWT access tokens. Nil disables them.
	Tokens AccessTokenVerifier

	// APIKeys validates API keys (Authorization: Bearer <key> or
	// X-API-Key). Nil disables them.
	APIKeys APIKeyValidator

	// Principals resolves token subjects and API key owners to app-local
	// principals (required).
	Principals PrincipalStore

	// Sessions, when set, also accepts a BFF cookie session for requests
	// without credentials, so one middleware protects an API used by both
	// the browser and programmatic clients.
	Sessions *BFF

	// AllowClientTokens accepts client-credentials access tokens (subject
	// equal to the client ID, no local principal) as a "client" principal.
	AllowClientTokens bool

	// Logger receives storage errors. Default: slog.Default().
	Logger *slog.Logger
}

// BearerMiddleware authenticates programmatic clients and puts an
// AuthenticatedPrincipal in the request context. It accepts, in order:
//
//   - Authorization: Bearer <JWT> — a SystemAuth JWT access token, verified
//     against the SystemAuth JWKS; its sub must be linked to a local
//     principal (sf_principal_id), who must have signed in to the app once.
//   - Authorization: Bearer <api key> or X-API-Key: <api key> — validated
//     by APIKeys; the key's owner is the principal.
//   - a BFF session cookie, when Sessions is set.
//
// Anything else gets 401 with a WWW-Authenticate: Bearer challenge.
func BearerMiddleware(cfg BearerConfig) func(http.Handler) http.Handler {
	if cfg.Principals == nil {
		panic("relyingparty: BearerConfig.Principals is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := cfg.authenticate(r)
			if err != nil {
				var authErr *bearerError
				if !errors.As(err, &authErr) {
					logger.ErrorContext(r.Context(), "authenticating request", "error", err)
					writeAuthError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
					return
				}
				challenge := `Bearer realm="api"`
				if authErr.code != "" {
					challenge += `, error="` + authErr.code + `"`
				}
				w.Header().Set("WWW-Authenticate", challenge)
				writeAuthError(w, http.StatusUnauthorized, "UNAUTHENTICATED", authErr.message)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// bearerError is an authentication failure reported to the client.
type bearerError struct {
	code    string
	message string
}

func (e *bearerError) Error() string { return e.message }

func errUnauthenticated(code, message string) error {
	return &bearerError{code: code, message: message}
}

func (cfg BearerConfig) authenticate(r *http.Request) (*AuthenticatedPrincipal, error) {
	ctx := r.Context()
	token := ""
	if auth := r.Header.Get("Authorization"); auth != "" {
		scheme, value, ok := strings.Cut(auth, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return nil, errUnauthenticated("invalid_request", "unsupported authorization scheme")
		}
		token = strings.TrimSpace(value)
	} else if key := r.Header.Get("X-API-Key"); key != "" {
		return cfg.authenticateAPIKey(ctx, key)
	}

	if token == "" {
		if cfg.Sessions != nil {
			p, err := cfg.Sessions.authenticate(r)
			if err == nil {
				return p, nil
			}
			if !errors.Is(err, ErrSessionNotFound) {
				return nil, err
			}
		}
		return nil, errUnauthenticated("", "authentication required")
	}

	if strings.Count(token, ".") == 2 {
		return cfg.authenticateJWT(ctx, token)
	}
	return cfg.authenticateAPIKey(ctx, token)
}

func (cfg BearerConfig) authenticateJWT(ctx context.Context, token string) (*AuthenticatedPrincipal, error) {
	if cfg.Tokens == nil {
		return nil, errUnauthenticated("invalid_token", "access tokens are not accepted")
	}
	claims, err := cfg.Tokens.VerifyAccessToken(ctx, token)
	if err != nil {
		return nil, errUnauthenticated("invalid_token", "invalid access token")
	}
	p, err := cfg.Principals.FindBySubject(ctx, claims.Subject)
	if errors.Is(err, ErrPrincipalNotFound) {
		if cfg.AllowClientTokens && claims.ClientID != "" && claims.Subject == claims.ClientID {
			return &AuthenticatedPrincipal{
				ID:      claims.ClientID,
				Type:    "client",
				Subject: claims.Subject,
				Method:  AuthMethodAccessToken,
				Scopes:  claims.Scopes,
			}, nil
		}
		return nil, errUnauthenticated("invalid_token", "unknown principal; sign in to the application first")
	}
	if err != nil {
		return nil, err
	}
	if !p.Active {
		return nil, errUnauthenticated("invalid_token", "principal is inactive")
	}
	memberships, err := cfg.Principals.Memberships(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	return &AuthenticatedPrincipal{
		ID:          p.ID,
		Type:        principalType(p),
		Subject:     claims.Subject,
		Method:      AuthMethodAccessToken,
		Scopes:      claims.Scopes,
		Memberships: memberships,
	}, nil
}

func (cfg BearerConfig) authenticateAPIKey(ctx context.Context, key string) (*AuthenticatedPrincipal, error) {
	if cfg.APIKeys == nil {
		return nil, errUnauthenticated("invalid_token", "API keys are not accepted")
	}
	k, err := cfg.APIKeys.Validate(ctx, key)
	if err != nil {
		switch {
		case errors.Is(err, apikey.ErrInvalidKey), errors.Is(err, apikey.ErrKeyNotFound),
			errors.Is(err, apikey.ErrKeyExpired), errors.Is(err, apikey.ErrKeyRevoked):
			return nil, errUnauthenticated("invalid_token", "invalid API key")
		}
		return nil, err
	}
	p, err := cfg.Principals.GetPrincipal(ctx, k.OwnerID.String())
	if errors.Is(err, ErrPrincipalNotFound) {
		return nil, errUnauthenticated("invalid_token", "API key owner not found")
	}
	if err != nil {
		return nil, err
	}
	if !p.Active {
		return nil, errUnauthenticated("invalid_token", "principal is inactive")
	}
	memberships, err := cfg.Principals.Memberships(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if k.OrganizationID != nil {
		orgID := k.OrganizationID.String()
		scoped := memberships[:0:0]
		for _, m := range memberships {
			if m.OrganizationID == orgID {
				scoped = append(scoped, m)
			}
		}
		memberships = scoped
	}
	return &AuthenticatedPrincipal{
		ID:          p.ID,
		Type:        principalType(p),
		Subject:     p.SFPrincipalID,
		Method:      AuthMethodAPIKey,
		Scopes:      k.Scopes,
		Memberships: memberships,
		APIKeyID:    k.ID.String(),
	}, nil
}

func principalType(p *Principal) string {
	if p.Type == "" {
		return "human"
	}
	return p.Type
}
