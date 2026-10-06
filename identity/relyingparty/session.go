package relyingparty

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"
)

// Session is a server-side browser session of the application. The cookie
// carries only an opaque token; SystemAuth tokens never reach the browser.
type Session struct {
	// PrincipalID is the app-local principal.
	PrincipalID string
	// Subject is the SystemAuth principal ID (sf_principal_id).
	Subject string
	// AccessToken, RefreshToken and IDToken are the SystemAuth tokens.
	AccessToken  string
	RefreshToken string
	IDToken      string
	// AccessTokenExpiresAt is when AccessToken expires.
	AccessTokenExpiresAt time.Time
	// CreatedAt is when the session was established.
	CreatedAt time.Time
	// ExpiresAt is the absolute session expiry.
	ExpiresAt time.Time
}

// SessionStore persists sessions keyed by an opaque session token.
// Implementations should store only a hash of the token and must be safe
// for concurrent use.
type SessionStore interface {
	// Create stores session under token.
	Create(ctx context.Context, token string, session Session) error
	// Get returns the session for token, or ErrSessionNotFound when it is
	// unknown or expired.
	Get(ctx context.Context, token string) (Session, error)
	// Update replaces the session for token (e.g. after a token refresh).
	// It returns ErrSessionNotFound for an unknown token.
	Update(ctx context.Context, token string, session Session) error
	// Delete removes the session. Deleting an unknown token is not an error.
	Delete(ctx context.Context, token string) error
}

// MemorySessionStore is an in-memory SessionStore for a single instance.
type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	now      func() time.Time
}

// NewMemorySessionStore creates an empty in-memory session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: map[string]Session{}, now: time.Now}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Create implements SessionStore. Expired sessions are pruned.
func (s *MemorySessionStore) Create(_ context.Context, token string, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.sessions {
		if now.After(v.ExpiresAt) {
			delete(s.sessions, k)
		}
	}
	s.sessions[hashToken(token)] = session
	return nil
}

// Get implements SessionStore.
func (s *MemorySessionStore) Get(_ context.Context, token string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashToken(token)
	sess, ok := s.sessions[key]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	if s.now().After(sess.ExpiresAt) {
		delete(s.sessions, key)
		return Session{}, ErrSessionNotFound
	}
	return sess, nil
}

// Update implements SessionStore.
func (s *MemorySessionStore) Update(_ context.Context, token string, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashToken(token)
	if _, ok := s.sessions[key]; !ok {
		return ErrSessionNotFound
	}
	s.sessions[key] = session
	return nil
}

// Delete implements SessionStore.
func (s *MemorySessionStore) Delete(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, hashToken(token))
	return nil
}

var _ SessionStore = (*MemorySessionStore)(nil)

// LoginState is the server-side record of an in-flight login.
type LoginState struct {
	// Nonce is the OIDC nonce sent in the authorization request.
	Nonce string
	// Verifier is the PKCE code verifier.
	Verifier string
	// ReturnTo is the validated post-login target.
	ReturnTo string
	// ExpiresAt bounds how long the login may take.
	ExpiresAt time.Time
}

// LoginStateStore keeps in-flight login state keyed by the OAuth state
// value. Take must be single-use.
type LoginStateStore interface {
	// Put stores state.
	Put(ctx context.Context, state string, data LoginState) error
	// Take returns and removes the state, or ErrInvalidState when it is
	// unknown, already used or expired.
	Take(ctx context.Context, state string) (LoginState, error)
}

// MemoryLoginStateStore is an in-memory LoginStateStore for a single
// instance.
type MemoryLoginStateStore struct {
	mu     sync.Mutex
	states map[string]LoginState
	now    func() time.Time
}

// NewMemoryLoginStateStore creates an empty in-memory login state store.
func NewMemoryLoginStateStore() *MemoryLoginStateStore {
	return &MemoryLoginStateStore{states: map[string]LoginState{}, now: time.Now}
}

// Put implements LoginStateStore. Expired entries are pruned.
func (s *MemoryLoginStateStore) Put(_ context.Context, state string, data LoginState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, v := range s.states {
		if now.After(v.ExpiresAt) {
			delete(s.states, k)
		}
	}
	s.states[hashToken(state)] = data
	return nil
}

// Take implements LoginStateStore.
func (s *MemoryLoginStateStore) Take(_ context.Context, state string) (LoginState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashToken(state)
	data, ok := s.states[key]
	if !ok {
		return LoginState{}, ErrInvalidState
	}
	delete(s.states, key)
	if s.now().After(data.ExpiresAt) {
		return LoginState{}, ErrInvalidState
	}
	return data, nil
}

var _ LoginStateStore = (*MemoryLoginStateStore)(nil)

// randomToken returns 256 bits of randomness, URL-safe encoded.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
