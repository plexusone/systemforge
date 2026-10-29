package bff

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultCookieName is the session cookie name used when none is
// configured. The __Host- prefix makes browsers accept the cookie only
// when it is Secure, has Path=/ and no Domain, so a sibling subdomain
// cannot set or overwrite it (cookie tossing or session fixation).
const DefaultCookieName = "__Host-sf_session"

// InsecureCookieName is the default name when the cookie is not Secure
// (CookieConfig.AllowInsecure for local development over plain HTTP),
// since browsers reject a __Host- cookie without Secure.
const InsecureCookieName = "sf_session"

const (
	hostCookiePrefix   = "__Host-"
	secureCookiePrefix = "__Secure-"
)

// ErrInvalidCookieConfig is returned by CookieConfig.Validate for a cookie
// browsers would reject or that could be shared beyond the application.
var ErrInvalidCookieConfig = errors.New("invalid session cookie configuration")

// CookieConfig contains configuration for session cookies.
//
// The session cookie is always host-only: it has no Domain attribute, so
// it is never shared with sibling subdomains, any of which could otherwise
// read, set or overwrite it. Applications on different hosts each keep
// their own session cookie.
type CookieConfig struct {
	// Name is the cookie name. Default: DefaultCookieName
	// ("__Host-sf_session"), or InsecureCookieName ("sf_session") when the
	// cookie is not Secure. Give each application its own name when
	// several share a host.
	Name string

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
	// production; NewHandler logs a warning when the cookie is not Secure.
	AllowInsecure bool

	// HTTPOnly prevents JavaScript access to the cookie. The session
	// cookie is always HttpOnly; the field is kept for compatibility.
	HTTPOnly bool

	// SameSite controls cross-site cookie behavior. It must be
	// http.SameSiteStrictMode or http.SameSiteLaxMode: the origin check
	// that protects state-changing requests relies on the browser
	// withholding the cookie from cross-site subrequests, so
	// http.SameSiteNoneMode is refused by Validate (and NewHandler).
	// Default (zero or http.SameSiteDefaultMode): SameSiteStrictMode.
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
	// A bool left out of a config is indistinguishable from false, so the
	// flags that protect the session are not configurable downward: the
	// cookie is always HttpOnly, and Secure unless AllowInsecure says
	// otherwise.
	config.HTTPOnly = true
	if !config.AllowInsecure {
		config.Secure = true
	}

	// Apply defaults for zero values
	if config.Name == "" {
		if config.Secure {
			config.Name = DefaultCookieName
		} else {
			config.Name = InsecureCookieName
		}
	}
	if config.Path == "" {
		config.Path = "/"
	}
	if config.SameSite == 0 || config.SameSite == http.SameSiteDefaultMode {
		config.SameSite = http.SameSiteStrictMode
	}

	return &CookieManager{config: config}
}

// Validate reports a cookie configuration browsers would reject or that
// weakens the session: a SameSite other than Strict or Lax, a __Host- name
// with a Path other than "/" or without Secure, or a __Secure- name without
// Secure. Call it on CookieManager.Config(), after defaults are applied;
// NewHandler does.
func (c CookieConfig) Validate() error {
	if c.SameSite != http.SameSiteStrictMode && c.SameSite != http.SameSiteLaxMode {
		return fmt.Errorf("%w: SameSite must be Strict or Lax; SameSite=None would send the session cookie on cross-site requests", ErrInvalidCookieConfig)
	}
	if strings.HasPrefix(c.Name, hostCookiePrefix) {
		if c.Path != "/" {
			return fmt.Errorf("%w: a %s cookie must have Path=/", ErrInvalidCookieConfig, hostCookiePrefix)
		}
		if !c.Secure {
			return fmt.Errorf("%w: a %s cookie must be Secure; use InsecureCookieName for plain-HTTP development", ErrInvalidCookieConfig, hostCookiePrefix)
		}
	}
	if strings.HasPrefix(c.Name, secureCookiePrefix) && !c.Secure {
		return fmt.Errorf("%w: a %s cookie must be Secure", ErrInvalidCookieConfig, secureCookiePrefix)
	}
	return nil
}

// SetSessionCookie creates and sets a session cookie on the response.
func (m *CookieManager) SetSessionCookie(w http.ResponseWriter, sessionID string, expiry time.Time) {
	//nolint:gosec // G124: Cookie has Secure, HttpOnly, SameSite set from CookieConfig
	cookie := &http.Cookie{
		Name:     m.config.Name,
		Value:    sessionID,
		Path:     m.config.Path,
		Expires:  expiry,
		MaxAge:   m.config.MaxAge,
		Secure:   m.config.Secure,
		HttpOnly: m.config.HTTPOnly,
		SameSite: m.config.SameSite,
	}

	http.SetCookie(w, cookie)
}

// GetSessionID extracts the session ID from the request cookie.
// Returns empty string if the cookie is not present or its value is not a
// well-formed session ID (see ValidSessionID).
func (m *CookieManager) GetSessionID(r *http.Request) string {
	cookie, err := r.Cookie(m.config.Name)
	if err != nil || !ValidSessionID(cookie.Value) {
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
