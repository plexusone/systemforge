package multiapp

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/plexusone/systemforge/identity/dpopproof"
	"github.com/plexusone/systemforge/rls"
	"github.com/plexusone/systemforge/session/jwt"
	"github.com/plexusone/systemforge/session/middleware"
)

// MiddlewareConfig configures the multiapp middleware stack.
type MiddlewareConfig struct {
	// JWTService validates JWT tokens (required).
	JWTService *jwt.Service

	// RequireAuth requires authentication for all requests.
	// If false, requests without credentials are allowed through.
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

	// DPoP configures DPoP (RFC 9449), which AuthMiddleware requires by
	// default: a token must be bound to a key (cnf.jkt) and come with the
	// DPoP scheme and a fresh proof by that key for the request, carrying
	// the token's hash. DPoP.ReplayCache is required (NewRedisReplayCache
	// when several instances serve the apps). Set DPoP.BaseURL to the
	// external base URL clients use, including any path prefix a proxy
	// strips: the proof's htu must equal it plus the request path as this
	// server sees it. DPoP.AllowBearer is the explicit opt-in that also
	// accepts unbound bearer tokens; a DPoP-bound token is never accepted
	// as Bearer.
	DPoP middleware.DPoPConfig

	// OnError is called when authentication fails.
	// If nil, a default error response is sent.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
}

// ErrJWTServiceRequired is returned by AuthMiddleware without a
// MiddlewareConfig.JWTService.
var ErrJWTServiceRequired = errors.New("multiapp: MiddlewareConfig.JWTService is required")

// AuthMiddleware returns middleware that validates access tokens and sets
// authentication context. This works with the app context middleware.
//
// It requires DPoP-bound tokens with a valid proof (see
// MiddlewareConfig.DPoP); unbound bearer tokens are refused unless
// DPoP.AllowBearer is set. It returns an error without a JWT service or a
// replay cache.
//
// The middleware chain should be:
//  1. appContextMiddleware (set by Server in multi-app mode)
//  2. AuthMiddleware (validates the token and its proof, sets claims)
//  3. Your handlers
func AuthMiddleware(cfg MiddlewareConfig) (func(http.Handler) http.Handler, error) {
	if cfg.JWTService == nil {
		return nil, ErrJWTServiceRequired
	}
	auth, err := middleware.NewDPoPAuth(cfg.JWTService, cfg.DPoP)
	if err != nil {
		return nil, fmt.Errorf("multiapp: %w", err)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			if !hasTokenCredentials(r) {
				if cfg.RequireAuth {
					writeChallenges(w, cfg.DPoP.AllowBearer)
					handleAuthError(w, r, cfg.OnError, ErrNotAuthenticated)
					return
				}
				// No token, but auth not required - continue without claims
				next.ServeHTTP(w, r)
				return
			}

			// On an app route the token must be addressed to the app.
			var audiences []string
			if appCtx := AppContextFromContext(ctx); appCtx != nil && !cfg.AllowCrossAppTokens {
				audiences = cfg.appAudiences(appCtx)
				if len(audiences) == 0 {
					writeChallenges(w, cfg.DPoP.AllowBearer)
					handleAuthError(w, r, cfg.OnError, jwt.ErrAudienceMismatch)
					return
				}
			}
			claims, err := auth.Authenticate(r, audiences...)
			if err != nil {
				writeChallenges(w, cfg.DPoP.AllowBearer)
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
	}, nil
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

// hasTokenCredentials reports whether the request carries an access token
// with the Bearer or DPoP scheme.
func hasTokenCredentials(r *http.Request) bool {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || strings.TrimSpace(token) == "" {
		return false
	}
	switch strings.ToLower(scheme) {
	case "bearer", "dpop":
		return true
	}
	return false
}

// writeChallenges sets the WWW-Authenticate challenges of a refused
// request (RFC 9449 §7.1): DPoP, and Bearer when bearer tokens are
// allowed.
func writeChallenges(w http.ResponseWriter, allowBearer bool) {
	w.Header().Add("WWW-Authenticate", `DPoP algs="`+strings.Join(dpopproof.Algorithms, " ")+`"`)
	if allowBearer {
		w.Header().Add("WWW-Authenticate", "Bearer")
	}
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
