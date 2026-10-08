package bff

import (
	"net/http"
	"time"
)

// DefaultCookieName is the session cookie name used when none is configured.
const DefaultCookieName = "sf_session"

// CookieConfig contains configuration for session cookies.
type CookieConfig struct {
	// Name is the cookie name. Default: DefaultCookieName ("sf_session").
	Name string

	// Domain is the cookie domain. If empty, uses the request host.
	Domain string

	// Path is the cookie path. Default: "/".
	Path string

	// MaxAge is the cookie max age in seconds. Default: 0 (session cookie).
	// Set to -1 to delete the cookie.
	MaxAge int

	// Secure indicates the cookie should only be sent over HTTPS. The
	// cookie is always Secure unless AllowInsecure is set, so a config
	// that leaves this field out cannot weaken it.
	Secure bool

	// AllowInsecure permits a cookie without the Secure flag when Secure
	// is false, for local development over plain HTTP. Never set it in
	// production.
	AllowInsecure bool

	// HTTPOnly prevents JavaScript access to the cookie. The session
	// cookie is always HttpOnly; the field is kept for compatibility.
	HTTPOnly bool

	// SameSite controls cross-site cookie behavior.
	// Default: SameSiteStrictMode.
	SameSite http.SameSite
}

// DefaultCookieConfig returns secure default cookie configuration.
func DefaultCookieConfig() CookieConfig {
	return CookieConfig{
		Name:     DefaultCookieName,
		Path:     "/",
		Secure:   true,
		HTTPOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// CookieManager handles session cookie operations.
type CookieManager struct {
	config CookieConfig
}

// NewCookieManager creates a new cookie manager with the given configuration.
func NewCookieManager(config CookieConfig) *CookieManager {
	// Apply defaults for zero values
	if config.Name == "" {
		config.Name = DefaultCookieName
	}
	if config.Path == "" {
		config.Path = "/"
	}
	if config.SameSite == 0 {
		config.SameSite = http.SameSiteStrictMode
	}
	// A bool left out of a config is indistinguishable from false, so the
	// flags that protect the session are not configurable downward: the
	// cookie is always HttpOnly, and Secure unless AllowInsecure says
	// otherwise.
	config.HTTPOnly = true
	if !config.AllowInsecure {
		config.Secure = true
	}

	return &CookieManager{config: config}
}

// SetSessionCookie creates and sets a session cookie on the response.
func (m *CookieManager) SetSessionCookie(w http.ResponseWriter, sessionID string, expiry time.Time) {
	//nolint:gosec // G124: Cookie has Secure, HttpOnly, SameSite set from CookieConfig
	cookie := &http.Cookie{
		Name:     m.config.Name,
		Value:    sessionID,
		Path:     m.config.Path,
		Domain:   m.config.Domain,
		Expires:  expiry,
		MaxAge:   m.config.MaxAge,
		Secure:   m.config.Secure,
		HttpOnly: m.config.HTTPOnly,
		SameSite: m.config.SameSite,
	}

	http.SetCookie(w, cookie)
}

// GetSessionID extracts the session ID from the request cookie.
// Returns empty string if the cookie is not present.
func (m *CookieManager) GetSessionID(r *http.Request) string {
	cookie, err := r.Cookie(m.config.Name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// ClearSessionCookie removes the session cookie from the response.
func (m *CookieManager) ClearSessionCookie(w http.ResponseWriter) {
	//nolint:gosec // G124: Cookie has Secure, HttpOnly, SameSite set from CookieConfig
	cookie := &http.Cookie{
		Name:     m.config.Name,
		Value:    "",
		Path:     m.config.Path,
		Domain:   m.config.Domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   m.config.Secure,
		HttpOnly: m.config.HTTPOnly,
		SameSite: m.config.SameSite,
	}

	http.SetCookie(w, cookie)
}

// Config returns the cookie configuration.
func (m *CookieManager) Config() CookieConfig {
	return m.config
}
