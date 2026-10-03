package systemauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Common authentication errors.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session expired")
	ErrSessionRevoked     = errors.New("session revoked")
)

// EmbeddedAuthProvider implements AuthenticationProvider with in-memory session storage.
// For production, use a persistent session store (Redis, database, etc.).
type EmbeddedAuthProvider struct {
	identityProvider IdentityProvider
	sessions         map[string]*storedSession
	sessionsByUser   map[uuid.UUID][]string // identity ID -> session tokens
	sessionDuration  time.Duration
	mu               sync.RWMutex

	// passwordVerifier is called to verify passwords.
	// If nil, password authentication is disabled.
	passwordVerifier func(ctx context.Context, identityID uuid.UUID, password string) (bool, error)
}

type storedSession struct {
	session   *AuthSession
	revokedAt *time.Time
}

// EmbeddedAuthProviderOption configures an EmbeddedAuthProvider.
type EmbeddedAuthProviderOption func(*EmbeddedAuthProvider)

// WithSessionDuration sets the session duration.
func WithSessionDuration(d time.Duration) EmbeddedAuthProviderOption {
	return func(p *EmbeddedAuthProvider) {
		p.sessionDuration = d
	}
}

// WithPasswordVerifier sets the password verification function.
func WithPasswordVerifier(verifier func(ctx context.Context, identityID uuid.UUID, password string) (bool, error)) EmbeddedAuthProviderOption {
	return func(p *EmbeddedAuthProvider) {
		p.passwordVerifier = verifier
	}
}

// NewEmbeddedAuthProvider creates an AuthenticationProvider with in-memory sessions.
func NewEmbeddedAuthProvider(identityProvider IdentityProvider, opts ...EmbeddedAuthProviderOption) *EmbeddedAuthProvider {
	p := &EmbeddedAuthProvider{
		identityProvider: identityProvider,
		sessions:         make(map[string]*storedSession),
		sessionsByUser:   make(map[uuid.UUID][]string),
		sessionDuration:  24 * time.Hour,
	}

	for _, opt := range opts {
		opt(p)
	}

	// Start cleanup goroutine
	go p.cleanupExpiredSessions()

	return p
}

// Authenticate implements AuthenticationProvider.
func (p *EmbeddedAuthProvider) Authenticate(ctx context.Context, req *AuthenticateRequest) (*AuthSession, error) {
	// Look up identity by identifier (email)
	identity, err := p.identityProvider.GetIdentityByEmail(ctx, req.Identifier)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if identity.State != IdentityStateActive {
		return nil, ErrInvalidCredentials
	}

	// Verify credentials based on method
	switch req.Method {
	case AuthMethodPassword:
		if p.passwordVerifier == nil {
			return nil, errors.New("password authentication not configured")
		}
		valid, err := p.passwordVerifier(ctx, identity.ID, req.Password)
		if err != nil || !valid {
			return nil, ErrInvalidCredentials
		}

	case AuthMethodOIDC:
		// OIDC tokens are validated externally; if we get here, trust the token
		// In a real implementation, verify the OIDC token

	default:
		return nil, errors.New("unsupported authentication method")
	}

	// Create session
	return p.createSession(identity, req.Method, req.DeviceInfo)
}

// createSession creates a new session for an identity.
func (p *EmbeddedAuthProvider) createSession(identity *Identity, method AuthMethod, deviceInfo *DeviceInfo) (*AuthSession, error) {
	// Generate session token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	now := time.Now()
	session := &AuthSession{
		ID:                    uuid.NewString(),
		Token:                 token,
		IdentityID:            identity.ID,
		Identity:              identity,
		AuthenticatedAt:       now,
		ExpiresAt:             now.Add(p.sessionDuration),
		AuthenticationMethods: []AuthMethod{method},
		Active:                true,
		DeviceInfo:            deviceInfo,
	}

	// Store session
	p.mu.Lock()
	p.sessions[token] = &storedSession{session: session}
	p.sessionsByUser[identity.ID] = append(p.sessionsByUser[identity.ID], token)
	p.mu.Unlock()

	return session, nil
}

// ValidateSession implements AuthenticationProvider.
func (p *EmbeddedAuthProvider) ValidateSession(ctx context.Context, sessionToken string) (*AuthSession, error) {
	p.mu.RLock()
	stored, ok := p.sessions[sessionToken]
	p.mu.RUnlock()

	if !ok {
		return nil, ErrSessionNotFound
	}

	if stored.revokedAt != nil {
		return nil, ErrSessionRevoked
	}

	if time.Now().After(stored.session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	// Return a copy with Active = true
	session := *stored.session
	session.Active = true

	return &session, nil
}

// RefreshSession implements AuthenticationProvider.
func (p *EmbeddedAuthProvider) RefreshSession(ctx context.Context, sessionToken string) (*AuthSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	stored, ok := p.sessions[sessionToken]
	if !ok {
		return nil, ErrSessionNotFound
	}

	if stored.revokedAt != nil {
		return nil, ErrSessionRevoked
	}

	// Extend expiration
	stored.session.ExpiresAt = time.Now().Add(p.sessionDuration)
	stored.session.Active = true

	return stored.session, nil
}

// RevokeSession implements AuthenticationProvider.
func (p *EmbeddedAuthProvider) RevokeSession(ctx context.Context, sessionToken string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	stored, ok := p.sessions[sessionToken]
	if !ok {
		return ErrSessionNotFound
	}

	now := time.Now()
	stored.revokedAt = &now
	stored.session.Active = false

	return nil
}

// RevokeSessions implements AuthenticationProvider.
func (p *EmbeddedAuthProvider) RevokeSessions(ctx context.Context, identityID uuid.UUID) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	tokens, ok := p.sessionsByUser[identityID]
	if !ok {
		return nil
	}

	now := time.Now()
	for _, token := range tokens {
		if stored, ok := p.sessions[token]; ok {
			stored.revokedAt = &now
			stored.session.Active = false
		}
	}

	return nil
}

// ListSessions implements AuthenticationProvider.
func (p *EmbeddedAuthProvider) ListSessions(ctx context.Context, identityID uuid.UUID) ([]*AuthSession, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	tokens, ok := p.sessionsByUser[identityID]
	if !ok {
		return nil, nil
	}

	now := time.Now()
	var sessions []*AuthSession

	for _, token := range tokens {
		stored, ok := p.sessions[token]
		if !ok {
			continue
		}

		// Skip revoked sessions
		if stored.revokedAt != nil {
			continue
		}

		// Copy session and set active status
		session := *stored.session
		session.Active = now.Before(session.ExpiresAt)
		sessions = append(sessions, &session)
	}

	return sessions, nil
}

// cleanupExpiredSessions periodically removes expired sessions.
func (p *EmbeddedAuthProvider) cleanupExpiredSessions() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		now := time.Now()

		// Find expired sessions
		var expiredTokens []string
		for token, stored := range p.sessions {
			// Remove if expired more than 24 hours ago or revoked more than 24 hours ago
			expiredThreshold := now.Add(-24 * time.Hour)

			if stored.session.ExpiresAt.Before(expiredThreshold) {
				expiredTokens = append(expiredTokens, token)
			} else if stored.revokedAt != nil && stored.revokedAt.Before(expiredThreshold) {
				expiredTokens = append(expiredTokens, token)
			}
		}

		// Remove expired sessions
		for _, token := range expiredTokens {
			if stored, ok := p.sessions[token]; ok {
				// Remove from user's session list
				userTokens := p.sessionsByUser[stored.session.IdentityID]
				for i, t := range userTokens {
					if t == token {
						p.sessionsByUser[stored.session.IdentityID] = append(userTokens[:i], userTokens[i+1:]...)
						break
					}
				}
			}
			delete(p.sessions, token)
		}

		p.mu.Unlock()
	}
}

// Ensure EmbeddedAuthProvider implements AuthenticationProvider.
var _ AuthenticationProvider = (*EmbeddedAuthProvider)(nil)
