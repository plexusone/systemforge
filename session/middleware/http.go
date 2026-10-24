package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/plexusone/systemforge/observability"
	"github.com/plexusone/systemforge/session/jwt"
)

// HTTPAuth returns a standard http.Handler middleware that validates JWT tokens.
// It extracts the token from the Authorization header (Bearer scheme) and
// attaches the claims to the request context. Only access tokens addressed
// to the service's Config.Audience are accepted. A DPoP-bound token (one
// with a cnf.jkt claim) is refused, since without a verified proof it would
// work as a plain bearer token; use HTTPAuthDPoP on routes that accept
// DPoP-bound tokens.
func HTTPAuth(jwtService *jwt.Service) func(http.Handler) http.Handler {
	return HTTPAuthWithObservability(jwtService, nil)
}

// HTTPAuthForAudience is HTTPAuth for routes that serve one kind of client:
// it admits only access tokens addressed to one of the audiences (for
// example jwt.AudienceBFF on browser routes), so a token minted for
// another audience, such as a narrowly scoped API token, cannot be used
// as a full session. HTTPAuth accepts any token addressed to this
// application, whatever kind of client it was minted for.
func HTTPAuthForAudience(jwtService *jwt.Service, audiences ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearerToken(r)
			if token == "" {
				writeUnauthorized(w, "missing authorization header")
				return
			}
			claims, err := jwtService.ValidateAccessTokenForAudience(token, audiences...)
			if err != nil {
				writeUnauthorized(w, err.Error())
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

// HTTPAuthWithObservability returns JWT validation middleware with observability.
// If obs is nil, metrics are not recorded.
func HTTPAuthWithObservability(jwtService *jwt.Service, obs *observability.Observability) func(http.Handler) http.Handler {
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
				writeUnauthorized(w, err.Error())
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

// HTTPAuthOptional returns middleware that validates JWT tokens if present,
// but allows requests without tokens to proceed.
func HTTPAuthOptional(jwtService *jwt.Service) func(http.Handler) http.Handler {
	return HTTPAuthOptionalWithObservability(jwtService, nil)
}

// HTTPAuthOptionalWithObservability returns optional JWT validation middleware with observability.
// If obs is nil, metrics are not recorded.
func HTTPAuthOptionalWithObservability(jwtService *jwt.Service, obs *observability.Observability) func(http.Handler) http.Handler {
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
// Must be used after HTTPAuth middleware.
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
// Must be used after HTTPAuth middleware.
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
// Must be used after HTTPAuth middleware.
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
// Must be used after HTTPAuth middleware.
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
// Must be used after HTTPAuth middleware.
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
// Must be used after HTTPAuth middleware.
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

func writeUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error:   "unauthorized",
		Message: message,
	})
}

func writeForbidden(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(ErrorResponse{
		Error:   "forbidden",
		Message: message,
	})
}
