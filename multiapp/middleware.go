package multiapp

import (
	"net/http"

	"github.com/plexusone/systemforge/rls"
	"github.com/plexusone/systemforge/session/jwt"
	"github.com/plexusone/systemforge/session/middleware"
)

// MiddlewareConfig configures the multiapp middleware stack.
type MiddlewareConfig struct {
	// JWTService validates JWT tokens.
	JWTService *jwt.Service

	// RequireAuth requires authentication for all requests.
	// If false, unauthenticated requests are allowed through.
	RequireAuth bool

	// SetRLSContext automatically sets RLS context from JWT claims.
	SetRLSContext bool

	// AppAudiences binds a token to the app a request is routed to: when the
	// request has an app context, the token must carry one of the audiences
	// returned for that app, so a token minted for one app cannot be replayed
	// against another by changing the X-App-ID header. Default: the app's
	// AppID, so mint tokens with jwt.TokenOptions{Audience: []string{appID}}.
	AppAudiences func(app *AppContext) []string

	// AllowCrossAppTokens turns app binding off: a request with an app
	// context accepts any token addressed to the JWT service's own
	// Config.Audience, whichever app it was minted for. Set it only when a
	// token is meant to be valid in every app.
	AllowCrossAppTokens bool

	// OnError is called when authentication fails.
	// If nil, a default error response is sent.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
}

// AuthMiddleware returns middleware that validates JWT tokens and sets
// authentication context. This works with the app context middleware.
//
// The middleware chain should be:
//  1. appContextMiddleware (set by Server in multi-app mode)
//  2. AuthMiddleware (validates JWT, sets claims)
//  3. Your handlers
func AuthMiddleware(cfg MiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract token from Authorization header
			token := extractBearerToken(r)

			if token == "" {
				if cfg.RequireAuth {
					handleAuthError(w, r, cfg.OnError, ErrNotAuthenticated)
					return
				}
				// No token, but auth not required - continue without claims
				next.ServeHTTP(w, r)
				return
			}

			// Validate token
			if cfg.JWTService == nil {
				handleAuthError(w, r, cfg.OnError, ErrNotAuthenticated)
				return
			}

			var claims *jwt.Claims
			var err error
			if appCtx := AppContextFromContext(ctx); appCtx != nil && !cfg.AllowCrossAppTokens {
				claims, err = cfg.JWTService.ValidateAccessTokenForAudience(token, cfg.appAudiences(appCtx)...)
			} else {
				claims, err = cfg.JWTService.ValidateAccessToken(token)
			}
			if err != nil {
				handleAuthError(w, r, cfg.OnError, err)
				return
			}

			// Add claims to context
			ctx = middleware.ContextWithClaims(ctx, claims)

			// Optionally set RLS context from claims
			if cfg.SetRLSContext {
				ctx = WithRLSFromClaims(ctx)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// appAudiences returns the audiences a token must carry for app.
func (cfg MiddlewareConfig) appAudiences(app *AppContext) []string {
	if cfg.AppAudiences != nil {
		return cfg.AppAudiences(app)
	}
	if app.AppID == "" {
		return nil
	}
	return []string{app.AppID}
}

// extractBearerToken extracts the Bearer token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// handleAuthError sends an authentication error response.
func handleAuthError(w http.ResponseWriter, r *http.Request, onError func(http.ResponseWriter, *http.Request, error), err error) {
	if onError != nil {
		onError(w, r, err)
		return
	}
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// RequireApp returns middleware that requires app context to be present.
// Use this for routes that must have an app context.
func RequireApp() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasAppContext(r.Context()) {
				http.Error(w, "App context required", http.StatusBadRequest)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireFeature returns middleware that requires a specific feature to be enabled.
func RequireFeature(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasFeature(r.Context(), feature) {
				http.Error(w, "Feature not enabled", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuthentication returns middleware that requires valid authentication.
func RequireAuthentication() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := middleware.ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission returns middleware that requires a specific permission.
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !middleware.HasPermission(r.Context(), permission) {
				http.Error(w, "Permission denied", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns middleware that requires a specific role.
func RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !middleware.HasRole(r.Context(), role) {
				http.Error(w, "Role required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// InjectRLS returns middleware that sets RLS context from JWT claims.
// Use this after AuthMiddleware if you need RLS but didn't enable SetRLSContext.
func InjectRLS() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := WithRLSFromClaims(r.Context())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AppLogger returns middleware that adds app context to structured logging.
// This should be used after appContextMiddleware.
func AppLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		appCtx := AppContextFromContext(ctx)

		if appCtx != nil {
			// Log app context (integrate with your logging setup)
			// For chi, you might use middleware.WithValue or similar
			claims := middleware.ClaimsFromContext(ctx)
			tenantID := rls.TenantIDFromContext(ctx)

			// Add to request context for downstream logging
			// This is a simple approach - in production you'd use
			// structured logging with slog or similar
			_ = appCtx.AppID
			_ = claims
			_ = tenantID
		}

		next.ServeHTTP(w, r)
	})
}
