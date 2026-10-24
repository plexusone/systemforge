package bff

import (
	"net/http"
	"net/url"
	"strings"
)

// OriginConfig contains configuration for origin validation.
type OriginConfig struct {
	// AllowedOrigins is a list of allowed origins.
	// Origins should be in the format "https://example.com" (no trailing slash).
	AllowedOrigins []string

	// AllowedHosts is a list of allowed hosts (without scheme).
	// This is an alternative to AllowedOrigins for simpler configuration.
	AllowedHosts []string

	// OnError is called when origin validation fails.
	// If nil, returns 403 Forbidden.
	OnError func(w http.ResponseWriter, r *http.Request)

	// AllowMissingOrigin allows requests without Origin header.
	// Default: false (more secure).
	AllowMissingOrigin bool

	// CheckReferer uses Referer header as fallback when Origin is missing.
	// Default: true.
	CheckReferer bool

	// SkipMethods is a list of HTTP methods to skip origin validation.
	// Typically safe methods (GET, HEAD, OPTIONS) can be skipped.
	// Default: none (validate all methods).
	SkipMethods []string
}

// DefaultOriginConfig returns default origin validation configuration.
func DefaultOriginConfig() OriginConfig {
	return OriginConfig{
		CheckReferer:       true,
		AllowMissingOrigin: false,
	}
}

// OriginValidator validates request origins.
type OriginValidator struct {
	config         OriginConfig
	allowedOrigins map[string]bool
	allowedHosts   map[string]bool
	skipMethods    map[string]bool
}

// NewOriginValidator creates a new origin validator.
func NewOriginValidator(config OriginConfig) *OriginValidator {
	v := &OriginValidator{
		config:         config,
		allowedOrigins: make(map[string]bool),
		allowedHosts:   make(map[string]bool),
		skipMethods:    make(map[string]bool),
	}

	for _, origin := range config.AllowedOrigins {
		v.allowedOrigins[strings.ToLower(origin)] = true
	}

	for _, host := range config.AllowedHosts {
		v.allowedHosts[strings.ToLower(host)] = true
	}

	for _, method := range config.SkipMethods {
		v.skipMethods[strings.ToUpper(method)] = true
	}

	return v
}

// Middleware returns HTTP middleware that validates request origins.
func (v *OriginValidator) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip validation for certain methods if configured
			if v.skipMethods[r.Method] {
				next.ServeHTTP(w, r)
				return
			}

			if !v.ValidateRequest(r) {
				v.handleError(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ValidateRequest validates the request origin.
func (v *OriginValidator) ValidateRequest(r *http.Request) bool {
	// Try Origin header first
	origin := r.Header.Get("Origin")
	if origin != "" {
		return v.isAllowedOrigin(origin)
	}

	// Fall back to Referer if configured
	if v.config.CheckReferer {
		referer := r.Header.Get("Referer")
		if referer != "" {
			return v.isAllowedReferer(referer)
		}
	}

	// No Origin or Referer header
	return v.config.AllowMissingOrigin
}

// SafeMethodMiddleware returns middleware that checks the requests
// Middleware lets through because of SkipMethods (typically GET, HEAD and
// OPTIONS). Use it on routes where even a read carries the user's
// credentials, such as the API proxy: an upstream GET endpoint may change
// state, and a session cookie relaxed to SameSite=Lax is sent on cross-site
// top-level navigations.
//
// A request is allowed when its Origin is allowed; without Origin, when
// Sec-Fetch-Site is "same-origin"; without either, when the Referer (if
// CheckReferer is set) is allowed. A request with none of the three is
// allowed, since it does not come from a current browser.
func (v *OriginValidator) SafeMethodMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v.skipMethods[r.Method] && !v.validateSafeRequest(r) {
				v.handleError(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// validateSafeRequest implements the SafeMethodMiddleware check.
func (v *OriginValidator) validateSafeRequest(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return v.isAllowedOrigin(origin)
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	if v.config.CheckReferer {
		if referer := r.Header.Get("Referer"); referer != "" {
			return v.isAllowedReferer(referer)
		}
	}
	return true
}

// isAllowedOrigin checks if the origin is in the allow list.
func (v *OriginValidator) isAllowedOrigin(origin string) bool {
	origin = strings.ToLower(origin)

	// Check exact origin match
	if v.allowedOrigins[origin] {
		return true
	}

	// Check host match
	if len(v.allowedHosts) > 0 {
		u, err := url.Parse(origin)
		if err == nil && v.allowedHosts[strings.ToLower(u.Host)] {
			return true
		}
	}

	return false
}

// isAllowedReferer checks if the referer origin is in the allow list.
func (v *OriginValidator) isAllowedReferer(referer string) bool {
	u, err := url.Parse(referer)
	if err != nil {
		return false
	}

	// Extract origin from referer (scheme + host)
	origin := u.Scheme + "://" + u.Host
	return v.isAllowedOrigin(origin)
}

// handleError handles origin validation errors.
func (v *OriginValidator) handleError(w http.ResponseWriter, r *http.Request) {
	if v.config.OnError != nil {
		v.config.OnError(w, r)
		return
	}

	http.Error(w, "Forbidden: Invalid origin", http.StatusForbidden)
}

// OriginMiddleware creates origin validation middleware with the given allowed origins.
// This is a convenience function for simple use cases.
func OriginMiddleware(allowedOrigins ...string) func(http.Handler) http.Handler {
	validator := NewOriginValidator(OriginConfig{
		AllowedOrigins: allowedOrigins,
		CheckReferer:   true,
	})
	return validator.Middleware()
}
