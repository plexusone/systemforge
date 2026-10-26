package middleware

import (
	"net/http"

	"github.com/plexusone/systemforge/session/jwt"
)

// ChiAuth returns a Chi-compatible middleware that validates DPoP-bound
// access tokens. This is an alias for HTTPAuth since Chi uses the standard
// http.Handler interface.
//
// Usage with Chi:
//
//	auth, err := middleware.ChiAuth(jwtService, middleware.DPoPConfig{ReplayCache: cache})
//	if err != nil { ... }
//	r := chi.NewRouter()
//	r.Use(auth)
//	r.Get("/api/protected", protectedHandler)
func ChiAuth(jwtService *jwt.Service, cfg DPoPConfig) (func(http.Handler) http.Handler, error) {
	return HTTPAuth(jwtService, cfg)
}

// ChiAuthOptional returns a Chi-compatible middleware that validates
// DPoP-bound access tokens if present. This is an alias for
// HTTPAuthOptional since Chi uses the standard http.Handler interface.
func ChiAuthOptional(jwtService *jwt.Service, cfg DPoPConfig) (func(http.Handler) http.Handler, error) {
	return HTTPAuthOptional(jwtService, cfg)
}

// ChiRequireRole returns a Chi-compatible middleware that requires a specific role.
//
// Usage with Chi:
//
//	r.Group(func(r chi.Router) {
//	    r.Use(auth) // from middleware.ChiAuth
//	    r.Use(middleware.ChiRequireRole("admin"))
//	    r.Get("/api/admin", adminHandler)
//	})
func ChiRequireRole(role string) func(http.Handler) http.Handler {
	return RequireRole(role)
}

// ChiRequireAnyRole returns a Chi-compatible middleware that requires any of the specified roles.
func ChiRequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return RequireAnyRole(roles...)
}

// ChiRequirePermission returns a Chi-compatible middleware that requires a specific permission.
func ChiRequirePermission(permission string) func(http.Handler) http.Handler {
	return RequirePermission(permission)
}

// ChiRequireAnyPermission returns a Chi-compatible middleware that requires any of the specified permissions.
func ChiRequireAnyPermission(permissions ...string) func(http.Handler) http.Handler {
	return RequireAnyPermission(permissions...)
}

// ChiRequirePlatformAdmin returns a Chi-compatible middleware that requires platform admin status.
func ChiRequirePlatformAdmin() func(http.Handler) http.Handler {
	return RequirePlatformAdmin()
}

// ChiRequireOrganization returns a Chi-compatible middleware that requires organization context.
func ChiRequireOrganization() func(http.Handler) http.Handler {
	return RequireOrganization()
}
