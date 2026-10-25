package oauthclient

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// State management for CSRF protection

const (
	// StateCookieName is the default name for the OAuth state cookie. The
	// __Host- prefix makes browsers accept the cookie only when it is
	// Secure, has Path=/ and no Domain, so a sibling subdomain cannot set
	// or overwrite it. The name differs from SystemAuth's own login state
	// cookie so both can run on one host.
	StateCookieName = "__Host-sf_oauth_client_state"

	// InsecureStateCookieName is the default name when the cookie is not
	// Secure (StateManager.AllowInsecure, for local development over plain
	// HTTP), since browsers reject a __Host- cookie without Secure.
	InsecureStateCookieName = "sf_oauth_client_state"

	// StateCookieMaxAge is the default max age for the state cookie (5 minutes).
	StateCookieMaxAge = 5 * 60
)

const (
	hostCookiePrefix   = "__Host-"
	secureCookiePrefix = "__Secure-"
)

// ErrInvalidState is returned when an OAuth state value is unknown, already
// used, or expired.
var ErrInvalidState = errors.New("oauthclient: invalid or expired state")

// ErrInvalidStateCookieConfig is returned by StateManager.Validate and
// StateManager.SetStateCookie for a state cookie browsers would reject or
// that would not return on the provider's redirect.
var ErrInvalidStateCookieConfig = errors.New("oauthclient: invalid state cookie configuration")

// GenerateState generates a cryptographically secure random state string.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// StateManager handles OAuth state cookie management.
//
// The cookie is always HttpOnly, SameSite=Lax, Path=/ and host-only (no
// Domain). A zero-value or hand-built StateManager is secure: fields left
// out take the secure defaults when the cookie is written.
type StateManager struct {
	// CookieName is the cookie name. Default: StateCookieName, or
	// InsecureStateCookieName when the cookie is not Secure.
	CookieName string

	// MaxAge is the cookie max age in seconds. Default: StateCookieMaxAge.
	MaxAge int

	// Secure marks the cookie HTTPS-only. The cookie is always Secure
	// unless AllowInsecure is set, so leaving this field out cannot
	// weaken it.
	Secure bool

	// AllowInsecure permits a cookie without the Secure flag when Secure
	// is false, for local development over plain HTTP. Never set it in
	// production. NewStateManagerInsecure sets it and logs a warning.
	AllowInsecure bool

	// SameSite must be left unset (0 or http.SameSiteDefaultMode) or be
	// http.SameSiteLaxMode; the cookie is always written with Lax. Strict
	// would drop the cookie on the provider's cross-site redirect back to
	// the callback, and None would send it with every cross-site request,
	// so both are refused.
	SameSite http.SameSite
}

// NewStateManager creates a state manager with secure defaults: a
// __Host- name, Secure, HttpOnly and SameSite=Lax. For local development
// over plain HTTP, use NewStateManagerInsecure.
func NewStateManager() *StateManager {
	return &StateManager{
		CookieName: StateCookieName,
		MaxAge:     StateCookieMaxAge,
		Secure:     true,
		SameSite:   http.SameSiteLaxMode,
	}
}

// NewStateManagerInsecure creates a state manager for local development
// over plain HTTP: the cookie is named InsecureStateCookieName and is not
// Secure. It logs a warning to logger (slog.Default() when nil) so an
// insecure cookie left on in production shows up at startup. Never use it
// in production.
func NewStateManagerInsecure(logger *slog.Logger) *StateManager {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("oauthclient: the OAuth state cookie is not Secure; use this for local development over plain HTTP only")
	return &StateManager{
		CookieName:    InsecureStateCookieName,
		MaxAge:        StateCookieMaxAge,
		AllowInsecure: true,
		SameSite:      http.SameSiteLaxMode,
	}
}

// effective returns the configuration the cookie is written with: the
// manager's fields with defaults applied, and Secure forced unless
// AllowInsecure is set.
func (m *StateManager) effective() StateManager {
	c := *m
	if !c.AllowInsecure {
		c.Secure = true
	}
	if c.CookieName == "" {
		if c.Secure {
			c.CookieName = StateCookieName
		} else {
			c.CookieName = InsecureStateCookieName
		}
	}
	if c.MaxAge == 0 {
		c.MaxAge = StateCookieMaxAge
	}
	if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode {
		c.SameSite = http.SameSiteLaxMode
	}
	return c
}

// Validate reports a configuration that would write a state cookie
// browsers reject or that would not return on the provider's redirect: a
// SameSite other than Lax, a negative MaxAge, or a __Host- or __Secure-
// name without Secure. Call it at startup; SetStateCookie refuses an
// invalid configuration too.
func (m *StateManager) Validate() error {
	c := m.effective()
	if c.SameSite != http.SameSiteLaxMode {
		return fmt.Errorf("%w: SameSite must be Lax so the cookie returns on the provider's redirect", ErrInvalidStateCookieConfig)
	}
	if c.MaxAge < 0 {
		return fmt.Errorf("%w: MaxAge must not be negative", ErrInvalidStateCookieConfig)
	}
	if !c.Secure {
		if strings.HasPrefix(c.CookieName, hostCookiePrefix) {
			return fmt.Errorf("%w: a %s cookie must be Secure; use InsecureStateCookieName for plain-HTTP development", ErrInvalidStateCookieConfig, hostCookiePrefix)
		}
		if strings.HasPrefix(c.CookieName, secureCookiePrefix) {
			return fmt.Errorf("%w: a %s cookie must be Secure", ErrInvalidStateCookieConfig, secureCookiePrefix)
		}
	}
	return nil
}

// stateCookie builds the state cookie from an effective configuration.
func stateCookie(m StateManager, value string, maxAge int) *http.Cookie {
	//nolint:gosec // G124: HttpOnly and SameSite=Lax always; Secure unless AllowInsecure was set for local HTTP
	return &http.Cookie{
		Name:     m.CookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: m.SameSite,
	}
}

// SetStateCookie sets the OAuth state cookie. When the configuration is
// invalid (see Validate) it sets nothing and returns an error wrapping
// ErrInvalidStateCookieConfig.
func (m *StateManager) SetStateCookie(w http.ResponseWriter, state string) error {
	if err := m.Validate(); err != nil {
		return err
	}
	c := m.effective()
	http.SetCookie(w, stateCookie(c, state, c.MaxAge))
	return nil
}

// ValidateState validates the OAuth state against the cookie and clears it.
// Returns true if valid, false otherwise, including when the configuration
// is invalid (see Validate).
func (m *StateManager) ValidateState(w http.ResponseWriter, r *http.Request, state string) bool {
	if err := m.Validate(); err != nil {
		return false
	}
	c := m.effective()
	cookie, err := r.Cookie(c.CookieName)
	if err != nil {
		return false
	}

	// Clear the state cookie
	http.SetCookie(w, stateCookie(c, "", -1))

	if state == "" {
		return false
	}
	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) == 1
}

// StateData is the server-side record associated with an OAuth state value.
type StateData struct {
	// Provider is the provider the flow was started for.
	Provider string `json:"provider"`

	// RedirectURL is the (already validated) post-login destination.
	RedirectURL string `json:"redirect_url,omitempty"`

	// Nonce is an optional OpenID Connect nonce.
	Nonce string `json:"nonce,omitempty"`

	// PKCEVerifier is the PKCE code verifier for the token exchange.
	PKCEVerifier string `json:"pkce_verifier,omitempty"`
}

// StateStore persists OAuth state server-side between the login redirect and
// the callback. Implementations must make Take single-use.
//
// The in-memory implementation only works for a single server instance; use a
// shared store (Redis, database) when running more than one replica.
type StateStore interface {
	// Put stores data under state for ttl.
	Put(ctx context.Context, state string, data StateData, ttl time.Duration) error

	// Take returns and deletes the data for state. It returns ErrInvalidState
	// when the state is unknown or expired.
	Take(ctx context.Context, state string) (StateData, error)
}

// MemoryStateStore is a concurrency-safe, in-memory StateStore.
type MemoryStateStore struct {
	mu     sync.Mutex
	states map[string]stateEntry
	now    func() time.Time
}

type stateEntry struct {
	data   StateData
	expiry time.Time
}

// NewMemoryStateStore creates an empty in-memory state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		states: make(map[string]stateEntry),
		now:    time.Now,
	}
}

// Put implements StateStore. Expired entries are pruned on each call.
func (s *MemoryStateStore) Put(_ context.Context, state string, data StateData, ttl time.Duration) error {
	if state == "" {
		return errors.New("oauthclient: empty state")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, e := range s.states {
		if now.After(e.expiry) {
			delete(s.states, k)
		}
	}
	s.states[state] = stateEntry{data: data, expiry: now.Add(ttl)}
	return nil
}

// Take implements StateStore.
func (s *MemoryStateStore) Take(_ context.Context, state string) (StateData, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.states[state]
	if !ok {
		return StateData{}, ErrInvalidState
	}
	delete(s.states, state)
	if s.now().After(entry.expiry) {
		return StateData{}, ErrInvalidState
	}
	return entry.data, nil
}

var _ StateStore = (*MemoryStateStore)(nil)
