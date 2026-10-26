package systemauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	sfidentity "github.com/plexusone/systemforge/identity"
	"github.com/plexusone/systemforge/identity/security"
)

// Common authentication errors.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session expired")
	ErrSessionRevoked     = errors.New("session revoked")

	// ErrUnsupportedAuthMethod is returned by EmbeddedAuthProvider for an
	// authentication method it cannot verify. Only AuthMethodPassword is
	// supported; OIDC sign-in goes through social login or federation,
	// which verify the upstream token themselves.
	ErrUnsupportedAuthMethod = errors.New("unsupported authentication method")

	// ErrPasswordAuthNotConfigured is returned for password authentication
	// when the provider has no password verifier.
	ErrPasswordAuthNotConfigured = errors.New("password authentication not configured")

	// ErrAccountLocked is returned when too many failed password attempts
	// were made for an identifier. Identifiers lock whether or not an
	// account exists, so the error does not reveal which accounts do.
	ErrAccountLocked = security.ErrAccountLocked
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

	// lockout limits failed password attempts per identifier. Nil turns
	// the limit off.
	lockout *security.Lockout
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

// WithLockout sets the lockout that limits failed password attempts per
// identifier. The default is an in-memory lockout with
// security.DefaultLockoutConfig; pass one over shared storage, such as
// security.NewRedisLockoutStore, when several instances serve logins. Nil
// turns the limit off, for deployments that limit attempts elsewhere.
func WithLockout(l *security.Lockout) EmbeddedAuthProviderOption {
	return func(p *EmbeddedAuthProvider) {
		p.lockout = l
	}
}

// NewEmbeddedAuthProvider creates an AuthenticationProvider with in-memory sessions.
func NewEmbeddedAuthProvider(identityProvider IdentityProvider, opts ...EmbeddedAuthProviderOption) *EmbeddedAuthProvider {
	p := &EmbeddedAuthProvider{
		identityProvider: identityProvider,
		sessions:         make(map[string]*storedSession),
		sessionsByUser:   make(map[uuid.UUID][]string),
		sessionDuration:  24 * time.Hour,
		lockout:          security.NewLockout(security.NewMemoryLockoutStore()),
	}

	for _, opt := range opts {
		opt(p)
	}

	// Start cleanup goroutine
	go p.cleanupExpiredSessions()

	return p
}

// Authenticate implements AuthenticationProvider. Only AuthMethodPassword
// is supported.
//
// Failed password attempts count against the identifier's lockout whether
// or not an account exists, and an unknown or inactive account costs a
// password hash verification like a wrong password does, so neither the
// errors nor the timing say which email addresses have accounts.
func (p *EmbeddedAuthProvider) Authenticate(ctx context.Context, req *AuthenticateRequest) (*AuthSession, error) {
	// Managed principals have no email and no password, so an empty
	// identifier never signs in.
	if strings.TrimSpace(req.Identifier) == "" {
		return nil, ErrInvalidCredentials
	}
	if req.Method != AuthMethodPassword {
		// Every other method, AuthMethodOIDC included, has no verifier
		// here. Accepting one without checking a credential would sign in
		// anyone who names an email address.
		return nil, ErrUnsupportedAuthMethod
	}
	if p.passwordVerifier == nil {
		return nil, ErrPasswordAuthNotConfigured
	}

	var attempt *security.Attempt
	if p.lockout != nil {
		a, err := p.lockout.Begin(ctx, req.Identifier)
		if errors.Is(err, security.ErrAccountLocked) {
			return nil, ErrAccountLocked
		}
		if err != nil {
			return nil, fmt.Errorf("checking login lockout: %w", err)
		}
		attempt = a
	}

	identity, err := p.verifyPassword(ctx, req)
	if err != nil {
		if attempt != nil && errors.Is(attempt.Failure(ctx), security.ErrAccountLocked) {
			return nil, ErrAccountLocked
		}
		return nil, err
	}
	if attempt != nil {
		if err := attempt.Success(ctx); err != nil {
			return nil, fmt.Errorf("clearing login lockout: %w", err)
		}
	}

	return p.createSession(identity, req.Method, req.DeviceInfo)
}

// verifyPassword returns the active identity whose email and password the
// request names, or ErrInvalidCredentials.
func (p *EmbeddedAuthProvider) verifyPassword(ctx context.Context, req *AuthenticateRequest) (*Identity, error) {
	identity, err := p.identityProvider.GetIdentityByEmail(ctx, req.Identifier)
	if err != nil || identity.State != IdentityStateActive {
		burnVerification(req.Password)
		return nil, ErrInvalidCredentials
	}
	valid, err := p.passwordVerifier(ctx, identity.ID, req.Password)
	if err != nil {
		return nil, fmt.Errorf("verifying password: %w", err)
	}
	if !valid {
		return nil, ErrInvalidCredentials
	}
	return identity, nil
}

var (
	burnHashOnce sync.Once
	burnHash     string

	// burnVerification is a variable so tests can observe it.
	burnVerification = burnArgon2idVerification
)

// burnArgon2idVerification spends the time of verifying a password against
// an Argon2id hash with the default parameters, so that rejecting an
// unknown account takes as long as rejecting a wrong password.
func burnArgon2idVerification(password string) {
	burnHashOnce.Do(func() {
		h, err := sfidentity.HashPassword("burn-verification", nil)
		if err != nil {
			panic(fmt.Errorf("systemauth: hashing the verification placeholder: %w", err))
		}
		burnHash = h
	})
	// The result is meaningless; only the elapsed time matters.
	if _, err := sfidentity.VerifyPassword(password, burnHash); err != nil {
		panic(fmt.Errorf("systemauth: verifying against the placeholder: %w", err))
	}
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
