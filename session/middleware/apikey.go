// Package middleware provides HTTP middleware for authentication and authorization.
package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/identity/apikey"
	"github.com/plexusone/systemforge/observability"
)

const (
	// ContextKeyAPIKey is the context key for the validated API key.
	ContextKeyAPIKey contextKey = "api_key"

	// ContextKeyPrincipal is the context key for the authenticated principal.
	ContextKeyPrincipal contextKey = "principal"
)

// Principal represents an authenticated entity (user or API key).
type Principal struct {
	// Type is "user" or "api_key".
	Type string `json:"type"`

	// ID is the principal's unique identifier.
	ID uuid.UUID `json:"id"`

	// UserID is the user's ID (same as ID for users, owner ID for API keys).
	UserID uuid.UUID `json:"user_id"`

	// OrganizationID is the organization context (optional).
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`

	// Scopes are the permissions granted to this principal.
	Scopes []string `json:"scopes,omitempty"`

	// Environment is "live" or "test" for API keys.
	Environment string `json:"environment,omitempty"`

	// Metadata contains additional principal data.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// HasScope returns true if the principal has the given scope.
func (p *Principal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope || s == "*" {
			return true
		}
		// Check wildcard patterns like "read:*"
		if strings.HasSuffix(s, ":*") {
			prefix := strings.TrimSuffix(s, "*")
			if strings.HasPrefix(scope, prefix) {
				return true
			}
		}
	}
	return false
}

// IsAPIKey returns true if the principal is an API key.
func (p *Principal) IsAPIKey() bool {
	return p.Type == "api_key"
}

// IsUser returns true if the principal is a user.
func (p *Principal) IsUser() bool {
	return p.Type == "user"
}

// ErrAPIKeyOwnerNotAllowed is returned by an APIKeyOwnerCheck when a valid
// key's owner may no longer use it: the owner is deactivated or deleted,
// or is no longer a member of the key's organization.
var ErrAPIKeyOwnerNotAllowed = errors.New("API key owner no longer has access")

// APIKeyOwnerCheck confirms, on every request, that the owner of a valid
// key may still use it. It must check that key.OwnerID is an active
// principal and, when key.OrganizationID is set, that the owner is still an
// active member of that organization, and return ErrAPIKeyOwnerNotAllowed
// (possibly wrapped) when not. Any error refuses the request.
//
// A key's validity only proves who created it and what it was scoped to
// then; without this check, a key keeps asserting its organization after
// its owner was removed from it or deactivated.
type APIKeyOwnerCheck func(ctx context.Context, key *apikey.APIKey) error

// APIKeyMiddlewareConfig contains configuration for the API key middleware.
type APIKeyMiddlewareConfig struct {
	// Service is the API key service.
	Service *apikey.Service

	// OwnerCheck confirms that the key's owner still has access
	// (required). APIKeyMiddleware panics without it.
	OwnerCheck APIKeyOwnerCheck

	// RequiredScopes are scopes that must be present (all required).
	RequiredScopes []string

	// AnyScopes requires at least one of these scopes.
	AnyScopes []string

	// HeaderName is the header containing the API key.
	// Default: "Authorization" with "Bearer" scheme.
	HeaderName string

	// AllowQueryParam enables API key in query parameter.
	// Default: false (more secure).
	AllowQueryParam bool

	// QueryParamName is the query parameter name.
	// Default: "api_key".
	QueryParamName string

	// RecordUsage updates the last used timestamp on each request.
	// Default: true.
	RecordUsage bool

	// OnError is called when authentication fails.
	// If nil, returns 401 Unauthorized.
	OnError func(w http.ResponseWriter, r *http.Request, err error)

	// OnSuccess is called after successful authentication.
	OnSuccess func(r *http.Request, key *apikey.APIKey)

	// IPExtractor extracts the client IP from the request.
	// If nil, uses r.RemoteAddr.
	IPExtractor func(r *http.Request) string

	// Observability is the observability provider for metrics.
	// If nil, no metrics are recorded.
	Observability *observability.Observability
}

// DefaultAPIKeyMiddlewareConfig returns default configuration.
func DefaultAPIKeyMiddlewareConfig() APIKeyMiddlewareConfig {
	return APIKeyMiddlewareConfig{
		HeaderName:      "Authorization",
		QueryParamName:  "api_key",
		AllowQueryParam: false,
		RecordUsage:     true,
	}
}

// APIKeyMiddleware creates middleware that validates API keys and checks,
// with config.OwnerCheck, that each key's owner still has access. It panics
// when config.Service or config.OwnerCheck is nil.
func APIKeyMiddleware(config APIKeyMiddlewareConfig) func(http.Handler) http.Handler {
	if config.Service == nil {
		panic("middleware: APIKeyMiddlewareConfig.Service is required")
	}
	if config.OwnerCheck == nil {
		panic("middleware: APIKeyMiddlewareConfig.OwnerCheck is required")
	}
	if config.HeaderName == "" {
		config.HeaderName = "Authorization"
	}
	if config.QueryParamName == "" {
		config.QueryParamName = "api_key"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract API key from request
			key := extractAPIKey(r, config)
			if key == "" {
				if config.Observability != nil {
					config.Observability.RecordAPIKeyValidation(ctx, observability.ResultMissing)
				}
				handleAPIKeyError(w, r, config, apikey.ErrInvalidKey)
				return
			}

			// Validate the key
			validatedKey, err := config.Service.Validate(ctx, key)
			if err != nil {
				if config.Observability != nil {
					var result string
					switch err {
					case apikey.ErrKeyExpired:
						result = observability.ResultExpired
					case apikey.ErrKeyRevoked:
						result = observability.ResultRevoked
					default:
						result = observability.ResultInvalid
					}
					config.Observability.RecordAPIKeyValidation(ctx, result)
				}
				handleAPIKeyError(w, r, config, err)
				return
			}

			// The key is valid; its owner must still have access.
			if err := checkAPIKeyOwner(ctx, config.OwnerCheck, validatedKey); err != nil {
				if config.Observability != nil {
					config.Observability.RecordAPIKeyValidation(ctx, observability.ResultDenied)
				}
				handleAPIKeyError(w, r, config, err)
				return
			}

			// Check required scopes
			if len(config.RequiredScopes) > 0 {
				if !validatedKey.HasAllScopes(config.RequiredScopes...) {
					if config.Observability != nil {
						config.Observability.RecordAPIKeyValidation(ctx, observability.ResultDenied)
					}
					handleAPIKeyError(w, r, config, apikey.ErrScopeNotAllowed)
					return
				}
			}

			// Check any scopes
			if len(config.AnyScopes) > 0 {
				if !validatedKey.HasAnyScope(config.AnyScopes...) {
					if config.Observability != nil {
						config.Observability.RecordAPIKeyValidation(ctx, observability.ResultDenied)
					}
					handleAPIKeyError(w, r, config, apikey.ErrScopeNotAllowed)
					return
				}
			}

			// Record successful validation
			if config.Observability != nil {
				config.Observability.RecordAPIKeyValidation(ctx, observability.ResultValid)
			}

			// Record usage
			if config.RecordUsage {
				ip := extractIP(r, config)
				// Fire and forget - don't block the request
				//nolint:gosec // G118: Background context intentional for fire-and-forget usage recording
				go func() {
					_ = config.Service.RecordUsage(context.Background(), validatedKey.ID, ip)
				}()
			}

			// Call success hook
			if config.OnSuccess != nil {
				config.OnSuccess(r, validatedKey)
			}

			// Create principal
			principal := &Principal{
				Type:           "api_key",
				ID:             validatedKey.ID,
				UserID:         validatedKey.OwnerID,
				OrganizationID: validatedKey.OrganizationID,
				Scopes:         validatedKey.Scopes,
				Environment:    string(validatedKey.Environment),
				Metadata:       validatedKey.Metadata,
			}

			// Add to context
			ctx = context.WithValue(ctx, ContextKeyAPIKey, validatedKey)
			ctx = context.WithValue(ctx, ContextKeyPrincipal, principal)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// checkAPIKeyOwner runs check for key. It returns ErrAPIKeyOwnerNotAllowed
// when the owner no longer has access, and logs and returns any other
// error, which also refuses the request.
func checkAPIKeyOwner(ctx context.Context, check APIKeyOwnerCheck, key *apikey.APIKey) error {
	err := check(ctx, key)
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrAPIKeyOwnerNotAllowed) {
		return ErrAPIKeyOwnerNotAllowed
	}
	slog.ErrorContext(ctx, "checking API key owner", "key_id", key.ID, "error", err)
	return err
}

// extractAPIKey extracts the API key from the request.
func extractAPIKey(r *http.Request, config APIKeyMiddlewareConfig) string {
	// Try header first
	auth := r.Header.Get(config.HeaderName)
	if auth != "" {
		// Support "Bearer <key>" format
		if _, found := strings.CutPrefix(strings.ToLower(auth), "bearer "); found {
			// Get the actual token with original case
			return auth[7:] // len("Bearer ") = 7
		} else if _, found = strings.CutPrefix(strings.ToLower(auth), "apikey "); found {
			return auth[7:] // len("ApiKey ") = 7
		}
		// Plain key in header
		return auth
	}

	// Try query parameter if allowed
	if config.AllowQueryParam {
		return r.URL.Query().Get(config.QueryParamName)
	}

	return ""
}

// extractIP returns the address recorded for an API key use: the
// configured IPExtractor's, or the direct peer's. Forwarding headers are
// never read here, since any caller can set them and they would otherwise
// forge the usage record; behind a proxy supply an IPExtractor such as
// ratelimit.ForwardedClientIP.
func extractIP(r *http.Request, config APIKeyMiddlewareConfig) string {
	if config.IPExtractor != nil {
		return config.IPExtractor(r)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if addr, err := netip.ParseAddr(strings.TrimSpace(host)); err == nil {
		return addr.Unmap().String()
	}
	return ""
}

// handleAPIKeyError handles API key authentication errors.
func handleAPIKeyError(w http.ResponseWriter, r *http.Request, config APIKeyMiddlewareConfig, err error) {
	if config.OnError != nil {
		config.OnError(w, r, err)
		return
	}

	switch err {
	case apikey.ErrInvalidKey:
		http.Error(w, "Unauthorized: Invalid API key", http.StatusUnauthorized)
	case apikey.ErrKeyExpired:
		http.Error(w, "Unauthorized: API key expired", http.StatusUnauthorized)
	case apikey.ErrKeyRevoked:
		http.Error(w, "Unauthorized: API key revoked", http.StatusUnauthorized)
	case ErrAPIKeyOwnerNotAllowed:
		http.Error(w, "Unauthorized: API key owner no longer has access", http.StatusUnauthorized)
	case apikey.ErrScopeNotAllowed:
		http.Error(w, "Forbidden: Insufficient permissions", http.StatusForbidden)
	default:
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

// GetAPIKey retrieves the validated API key from the request context.
func GetAPIKey(ctx context.Context) *apikey.APIKey {
	key, _ := ctx.Value(ContextKeyAPIKey).(*apikey.APIKey)
	return key
}

// GetPrincipal retrieves the authenticated principal from the request context.
func GetPrincipal(ctx context.Context) *Principal {
	principal, _ := ctx.Value(ContextKeyPrincipal).(*Principal)
	return principal
}

// RequireAPIKey creates middleware that requires a valid API key whose
// owner passes ownerCheck. This is a convenience function with default
// configuration.
func RequireAPIKey(service *apikey.Service, ownerCheck APIKeyOwnerCheck) func(http.Handler) http.Handler {
	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = service
	config.OwnerCheck = ownerCheck
	return APIKeyMiddleware(config)
}

// RequireAPIKeyWithScopes creates middleware that requires specific scopes.
func RequireAPIKeyWithScopes(service *apikey.Service, ownerCheck APIKeyOwnerCheck, scopes ...string) func(http.Handler) http.Handler {
	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = service
	config.OwnerCheck = ownerCheck
	config.RequiredScopes = scopes
	return APIKeyMiddleware(config)
}

// OptionalAPIKey creates middleware that validates API keys if present but
// doesn't require them. A key that is invalid, or whose owner fails
// ownerCheck, leaves the request unauthenticated. It panics when service or
// ownerCheck is nil.
func OptionalAPIKey(service *apikey.Service, ownerCheck APIKeyOwnerCheck) func(http.Handler) http.Handler {
	if service == nil || ownerCheck == nil {
		panic("middleware: OptionalAPIKey requires a service and an owner check")
	}
	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = service

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract API key from request
			key := extractAPIKey(r, config)
			if key == "" {
				// No key provided - continue without authentication
				next.ServeHTTP(w, r)
				return
			}

			// Validate the key
			validatedKey, err := config.Service.Validate(r.Context(), key)
			if err != nil {
				// Invalid key - continue without authentication
				next.ServeHTTP(w, r)
				return
			}
			if err := checkAPIKeyOwner(r.Context(), ownerCheck, validatedKey); err != nil {
				// The owner no longer has access - continue without
				// authentication
				next.ServeHTTP(w, r)
				return
			}

			// Record usage
			if config.RecordUsage {
				ip := extractIP(r, config)
				//nolint:gosec // G118: Background context intentional for fire-and-forget usage recording
				go func() {
					_ = config.Service.RecordUsage(context.Background(), validatedKey.ID, ip)
				}()
			}

			// Create principal
			principal := &Principal{
				Type:           "api_key",
				ID:             validatedKey.ID,
				UserID:         validatedKey.OwnerID,
				OrganizationID: validatedKey.OrganizationID,
				Scopes:         validatedKey.Scopes,
				Environment:    string(validatedKey.Environment),
				Metadata:       validatedKey.Metadata,
			}

			// Add to context
			ctx := context.WithValue(r.Context(), ContextKeyAPIKey, validatedKey)
			ctx = context.WithValue(ctx, ContextKeyPrincipal, principal)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScope creates middleware that checks for a specific scope.
// This should be used after APIKeyMiddleware.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := GetPrincipal(r.Context())
			if principal == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if !principal.HasScope(scope) {
				http.Error(w, "Forbidden: Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyScope creates middleware that checks for any of the given scopes.
func RequireAnyScope(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal := GetPrincipal(r.Context())
			if principal == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			for _, scope := range scopes {
				if principal.HasScope(scope) {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Forbidden: Insufficient permissions", http.StatusForbidden)
		})
	}
}
