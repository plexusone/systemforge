package middleware

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/plexusone/systemforge/internal/apierror"
	"github.com/plexusone/systemforge/observability"
	"github.com/plexusone/systemforge/session/jwt"
)

// The HTTPAuthBearer middlewares are the legacy, explicit opt-in for
// routes that accept unbound bearer tokens only. Whoever holds a bearer
// token can use it, so the default middlewares, HTTPAuth, HTTPAuthForAudience
// and HTTPAuthOptional, require DPoP-bound tokens with a proof (RFC 9449)
// unless DPoPConfig.AllowBearer is set. The bearer middlewares still refuse
// a DPoP-bound token (one with a cnf.jkt claim), since without a verified
// proof it would work as a plain bearer token.

// HTTPAuthBearer returns middleware that validates unbound bearer JWTs: it
// extracts the token from the Authorization header (Bearer scheme) and
// attaches the claims to the request context. Only access tokens addressed
// to the service's Config.Audience are accepted, and a DPoP-bound token is
// refused. Prefer HTTPAuth, which requires DPoP.
func HTTPAuthBearer(jwtService *jwt.Service) func(http.Handler) http.Handler {
	return HTTPAuthBearerWithObservability(jwtService, nil)
}

// HTTPAuthBearerForAudience is HTTPAuthBearer for routes that serve one
// kind of client: it admits only access tokens addressed to one of the
// audiences (for example jwt.AudienceBFF on browser routes), so a token
// minted for another audience, such as a narrowly scoped API token, cannot
// be used as a full session. Prefer HTTPAuthForAudience, which requires
// DPoP.
func HTTPAuthBearerForAudience(jwtService *jwt.Service, audiences ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				writeUnauthorized(w, "missing authorization header")
				return
			}
			claims, err := jwtService.ValidateAccessTokenForAudience(token, audiences...)
			if err != nil {
				writeUnauthorized(w, unauthorizedMessage(r, err))
				return
			}
			if claims.IsDPoPBound() {
				writeUnauthorized(w, ErrDPoPProofRequired.Error())
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithClaims(r.Context(), claims)))
		})
	}
}

// HTTPAuthBearerWithObservability is HTTPAuthBearer with observability.
// If obs is nil, metrics are not recorded.
func HTTPAuthBearerWithObservability(jwtService *jwt.Service, obs *observability.Observability) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			start := time.Now()

			token := extractBearerToken(r)
			if token == "" {
				if obs != nil {
					obs.RecordJWTValidation(ctx, observability.ResultMissing)
				}
				writeUnauthorized(w, "missing authorization header")
				return
			}

			claims, err := jwtService.ValidateAccessToken(token)
			if err == nil && claims.IsDPoPBound() {
				err = ErrDPoPProofRequired
			}
			if err != nil {
				if obs != nil {
					obs.RecordJWTValidation(ctx, observability.ResultInvalid)
					obs.RecordJWTLatency(ctx, float64(time.Since(start).Milliseconds()))
				}
				writeUnauthorized(w, unauthorizedMessage(r, err))
				return
			}

			if obs != nil {
				obs.RecordJWTValidation(ctx, observability.ResultValid)
				obs.RecordJWTLatency(ctx, float64(time.Since(start).Milliseconds()))
			}

			ctx = ContextWithClaims(ctx, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// HTTPAuthBearerOptional is HTTPAuthBearer that lets requests without a
// valid token through without claims. Prefer HTTPAuthOptional, which
// requires DPoP.
func HTTPAuthBearerOptional(jwtService *jwt.Service) func(http.Handler) http.Handler {
	return HTTPAuthBearerOptionalWithObservability(jwtService, nil)
}

// HTTPAuthBearerOptionalWithObservability is HTTPAuthBearerOptional with
// observability. If obs is nil, metrics are not recorded.
func HTTPAuthBearerOptionalWithObservability(jwtService *jwt.Service, obs *observability.Observability) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			start := time.Now()

			token := extractBearerToken(r)
			if token != "" {
				claims, err := jwtService.ValidateAccessToken(token)
				if err == nil && claims.IsDPoPBound() {
					err = ErrDPoPProofRequired
				}
				if err == nil {
					if obs != nil {
						obs.RecordJWTValidation(ctx, observability.ResultValid)
						obs.RecordJWTLatency(ctx, float64(time.Since(start).Milliseconds()))
					}
					ctx = ContextWithClaims(ctx, claims)
					r = r.WithContext(ctx)
				} else if obs != nil {
					obs.RecordJWTValidation(ctx, observability.ResultInvalid)
					obs.RecordJWTLatency(ctx, float64(time.Since(start).Milliseconds()))
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns middleware that requires the user to have a specific role.
// Must be used after HTTPAuth (or HTTPAuthBearer) middleware.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasRole(r.Context(), role) {
				writeForbidden(w, "insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole returns middleware that requires the user to have any of the specified roles.
// Must be used after HTTPAuth (or HTTPAuthBearer) middleware.
func RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasAnyRole(r.Context(), roles...) {
				writeForbidden(w, "insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission returns middleware that requires a specific permission.
// Must be used after HTTPAuth (or HTTPAuthBearer) middleware.
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasPermission(r.Context(), permission) {
				writeForbidden(w, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPermission returns middleware that requires any of the specified permissions.
// Must be used after HTTPAuth (or HTTPAuthBearer) middleware.
func RequireAnyPermission(permissions ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasAnyPermission(r.Context(), permissions...) {
				writeForbidden(w, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePlatformAdmin returns middleware that requires platform admin status.
// Must be used after HTTPAuth (or HTTPAuthBearer) middleware.
func RequirePlatformAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !IsPlatformAdminFromContext(r.Context()) {
				writeForbidden(w, "platform admin required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireOrganization returns middleware that requires an organization context.
// Must be used after HTTPAuth (or HTTPAuthBearer) middleware.
func RequireOrganization() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if OrganizationIDFromContext(r.Context()) == nil {
				writeForbidden(w, "organization context required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// extractBearerToken extracts the JWT token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return parts[1]
}

// ErrorResponse represents an error response body.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// unauthorizedMessage is the response message for an authentication
// failure. Token and proof errors map to their fixed sentinel text, so
// parser, key and replay-cache details never reach the client; an
// unexpected error is logged and answered generically.
func unauthorizedMessage(r *http.Request, err error) string {
	for _, known := range []error{
		ErrMissingAuthorization,
		ErrDPoPProofRequired,
		ErrDPoPTokenNotBound,
		ErrDPoPProofReplayed,
		ErrBearerTokenRefused,
		jwt.ErrTokenExpired,
	} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	switch {
	case errors.Is(err, jwt.ErrInvalidToken),
		errors.Is(err, jwt.ErrWrongTokenType),
		errors.Is(err, jwt.ErrAudienceMismatch),
		errors.Is(err, jwt.ErrInvalidAlgorithm):
		return jwt.ErrInvalidToken.Error()
	}
	apierror.Log(r.Context(), nil, "authenticating request", err)
	return "authentication failed"
}

func writeUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:   "unauthorized",
		Message: message,
	}); err != nil {
		// The status is sent; only the body was lost.
		slog.Default().Error("writing unauthorized response", "error", err)
	}
}

func writeForbidden(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:   "forbidden",
		Message: message,
	}); err != nil {
		// The status is sent; only the body was lost.
		slog.Default().Error("writing forbidden response", "error", err)
	}
}
