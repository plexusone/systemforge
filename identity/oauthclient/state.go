package oauthclient

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"
)

// State management for CSRF protection

const (
	// StateCookieName is the default name for the OAuth state cookie.
	StateCookieName = "oauth_state"
	// StateCookieMaxAge is the default max age for the state cookie (5 minutes).
	StateCookieMaxAge = 5 * 60
)

// ErrInvalidState is returned when an OAuth state value is unknown, already
// used, or expired.
var ErrInvalidState = errors.New("oauthclient: invalid or expired state")

// GenerateState generates a cryptographically secure random state string.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// StateManager handles OAuth state cookie management.
type StateManager struct {
	CookieName string
	MaxAge     int
	Secure     bool // Secure flag for cookies (default: true, requires HTTPS)
	SameSite   http.SameSite
}

// NewStateManager creates a state manager with secure defaults.
// Cookies are set with Secure: true, requiring HTTPS.
// For local development over HTTP, use NewStateManagerInsecure().
func NewStateManager() *StateManager {
	return &StateManager{
		CookieName: StateCookieName,
		MaxAge:     StateCookieMaxAge,
		Secure:     true,
		SameSite:   http.SameSiteLaxMode,
	}
}

// NewStateManagerInsecure creates a state manager for local development over HTTP.
// WARNING: Only use this for local development. Never use in production.
func NewStateManagerInsecure() *StateManager {
	return &StateManager{
		CookieName: StateCookieName,
		MaxAge:     StateCookieMaxAge,
		Secure:     false,
		SameSite:   http.SameSiteLaxMode,
	}
}

// SetStateCookie sets the OAuth state cookie.
func (m *StateManager) SetStateCookie(w http.ResponseWriter, state string) {
	//nolint:gosec // G124: Cookie has HttpOnly, Secure, SameSite set from StateManager config
	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   m.MaxAge,
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: m.SameSite,
	})
}

// ValidateState validates the OAuth state against the cookie and clears it.
// Returns true if valid, false otherwise.
func (m *StateManager) ValidateState(w http.ResponseWriter, r *http.Request, state string) bool {
	cookie, err := r.Cookie(m.CookieName)
	if err != nil {
		return false
	}

	// Clear the state cookie
	//nolint:gosec // G124: Cookie has HttpOnly=true, Secure/SameSite from StateManager (default secure)
	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: m.SameSite,
	})

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
