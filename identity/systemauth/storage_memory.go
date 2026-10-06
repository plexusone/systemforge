package systemauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// MemoryStorage implements the Storage interface using in-memory maps.
// This is suitable for embedded mode and testing.
type MemoryStorage struct {
	mu sync.RWMutex

	// Client storage
	clients map[string]*Client

	// Authorization code storage
	authCodes map[string]*storedAuthCode

	// Access token storage
	accessTokens map[string]*storedToken

	// Refresh token storage
	refreshTokens map[string]*storedToken

	// PKCE storage (shares with auth codes)
	pkceSessions map[string]*storedAuthCode

	// OpenID Connect sessions keyed by authorization code
	oidcSessions map[string]fosite.Requester

	// User storage for federation
	users map[uuid.UUID]*User
}

// storedAuthCode holds an authorization code with its request data.
type storedAuthCode struct {
	request   fosite.Requester
	expiresAt time.Time
	used      bool
}

// storedToken holds a token with its request data.
type storedToken struct {
	request   fosite.Requester
	requestID string
	expiresAt time.Time
	revoked   bool
}

// NewMemoryStorage creates a new in-memory storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		clients:       make(map[string]*Client),
		authCodes:     make(map[string]*storedAuthCode),
		accessTokens:  make(map[string]*storedToken),
		refreshTokens: make(map[string]*storedToken),
		pkceSessions:  make(map[string]*storedAuthCode),
		oidcSessions:  make(map[string]fosite.Requester),
		users:         make(map[uuid.UUID]*User),
	}
}

// hashSignature creates a SHA256 hash of a signature for storage keys.
func hashSignature(sig string) string {
	h := sha256.Sum256([]byte(sig))
	return hex.EncodeToString(h[:])
}

// --- fosite.ClientManager ---

// GetClient retrieves a client by ID (implements fosite.ClientManager).
func (s *MemoryStorage) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, ok := s.clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return client, nil
}

// --- Client Management ---

// CreateClient creates a new OAuth client.
func (s *MemoryStorage) CreateClient(ctx context.Context, client *Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[client.ID]; exists {
		return ErrClientExists
	}

	s.clients[client.ID] = client
	return nil
}

// GetClientByID retrieves a client by ID.
func (s *MemoryStorage) GetClientByID(ctx context.Context, id string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, ok := s.clients[id]
	if !ok {
		return nil, ErrClientNotFound
	}
	return client, nil
}

// UpdateClient updates an existing client.
func (s *MemoryStorage) UpdateClient(ctx context.Context, client *Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[client.ID]; !exists {
		return ErrClientNotFound
	}

	client.UpdatedAt = time.Now()
	s.clients[client.ID] = client
	return nil
}

// DeleteClient deletes a client.
func (s *MemoryStorage) DeleteClient(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[id]; !exists {
		return ErrClientNotFound
	}

	delete(s.clients, id)
	return nil
}

// ListClients returns all clients.
func (s *MemoryStorage) ListClients(ctx context.Context) ([]*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]*Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	return clients, nil
}

// --- Authorization Code Storage ---

// CreateAuthorizeCodeSession stores an authorization code session.
func (s *MemoryStorage) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sig := hashSignature(code)
	s.authCodes[sig] = &storedAuthCode{
		request:   request,
		expiresAt: request.GetSession().GetExpiresAt(fosite.AuthorizeCode),
		used:      false,
	}
	return nil
}

// GetAuthorizeCodeSession retrieves an authorization code session.
func (s *MemoryStorage) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sig := hashSignature(code)
	stored, ok := s.authCodes[sig]
	if !ok {
		return nil, fosite.ErrNotFound
	}

	if stored.used {
		return nil, fosite.ErrInvalidatedAuthorizeCode
	}

	if time.Now().After(stored.expiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	return stored.request, nil
}

// InvalidateAuthorizeCodeSession marks an authorization code as used.
func (s *MemoryStorage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sig := hashSignature(code)
	if stored, ok := s.authCodes[sig]; ok {
		stored.used = true
	}
	return nil
}

// --- Access Token Storage ---

// CreateAccessTokenSession stores an access token session.
func (s *MemoryStorage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sig := hashSignature(signature)
	s.accessTokens[sig] = &storedToken{
		request:   request,
		requestID: request.GetID(),
		expiresAt: request.GetSession().GetExpiresAt(fosite.AccessToken),
		revoked:   false,
	}
	return nil
}

// GetAccessTokenSession retrieves an access token session.
func (s *MemoryStorage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sig := hashSignature(signature)
	stored, ok := s.accessTokens[sig]
	if !ok {
		return nil, fosite.ErrNotFound
	}

	if stored.revoked {
		return nil, fosite.ErrInactiveToken
	}

	if time.Now().After(stored.expiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	return stored.request, nil
}

// DeleteAccessTokenSession removes an access token session.
func (s *MemoryStorage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sig := hashSignature(signature)
	delete(s.accessTokens, sig)
	return nil
}

// --- Refresh Token Storage ---

// CreateRefreshTokenSession stores a refresh token session.
func (s *MemoryStorage) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sig := hashSignature(signature)
	s.refreshTokens[sig] = &storedToken{
		request:   request,
		requestID: request.GetID(),
		expiresAt: request.GetSession().GetExpiresAt(fosite.RefreshToken),
		revoked:   false,
	}

	// Also store the access signature mapping if provided
	if accessSignature != "" {
		accessSig := hashSignature(accessSignature)
		s.accessTokens[accessSig] = &storedToken{
			request:   request,
			requestID: request.GetID(),
			expiresAt: request.GetSession().GetExpiresAt(fosite.AccessToken),
			revoked:   false,
		}
	}

	return nil
}

// GetRefreshTokenSession retrieves a refresh token session.
func (s *MemoryStorage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sig := hashSignature(signature)
	stored, ok := s.refreshTokens[sig]
	if !ok {
		return nil, fosite.ErrNotFound
	}

	if stored.revoked {
		// Return the request with ErrInactiveToken so Fosite can detect
		// refresh-token reuse and revoke the whole token family.
		return stored.request, fosite.ErrInactiveToken
	}

	if !stored.expiresAt.IsZero() && time.Now().After(stored.expiresAt) {
		return nil, fosite.ErrTokenExpired
	}

	return stored.request, nil
}

// DeleteRefreshTokenSession removes a refresh token session.
func (s *MemoryStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sig := hashSignature(signature)
	delete(s.refreshTokens, sig)
	return nil
}

// RevokeRefreshToken revokes all refresh tokens for a request ID.
func (s *MemoryStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, token := range s.refreshTokens {
		if token.requestID == requestID {
			token.revoked = true
		}
	}
	return nil
}

// RevokeAccessToken revokes all access tokens for a request ID.
func (s *MemoryStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, token := range s.accessTokens {
		if token.requestID == requestID {
			token.revoked = true
		}
	}
	return nil
}

// RotateRefreshToken retires the refresh and access tokens of a token
// family before Fosite issues their replacements. Retired refresh tokens
// stay stored (inactive) so that a later reuse is detected.
func (s *MemoryStorage) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, token := range s.refreshTokens {
		if token.requestID == requestID {
			token.revoked = true
		}
	}
	for _, token := range s.accessTokens {
		if token.requestID == requestID {
			token.revoked = true
		}
	}
	return nil
}

// RevokeSubjectTokens implements SubjectTokenRevoker.
func (s *MemoryStorage) RevokeSubjectTokens(ctx context.Context, subject string) error {
	if subject == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, m := range []map[string]*storedToken{s.accessTokens, s.refreshTokens} {
		for _, token := range m {
			if sessionSubject(token.request.GetSession()) == subject {
				token.revoked = true
			}
		}
	}
	return nil
}

// --- PKCE Storage ---

// CreatePKCERequestSession creates a PKCE session.
func (s *MemoryStorage) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sig := hashSignature(signature)
	s.pkceSessions[sig] = &storedAuthCode{
		request:   requester,
		expiresAt: requester.GetSession().GetExpiresAt(fosite.AuthorizeCode),
		used:      false,
	}
	return nil
}

// GetPKCERequestSession retrieves a PKCE session.
func (s *MemoryStorage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sig := hashSignature(signature)
	stored, ok := s.pkceSessions[sig]
	if !ok {
		// Fall back to auth codes (PKCE is often stored with auth code)
		stored, ok = s.authCodes[sig]
		if !ok {
			return nil, fosite.ErrNotFound
		}
	}

	return stored.request, nil
}

// DeletePKCERequestSession deletes a PKCE session.
func (s *MemoryStorage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sig := hashSignature(signature)
	delete(s.pkceSessions, sig)
	return nil
}

// --- OpenID Connect Sessions ---

// CreateOpenIDConnectSession stores the OIDC session for an authorization code.
func (s *MemoryStorage) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.oidcSessions[hashSignature(authorizeCode)] = requester
	return nil
}

// GetOpenIDConnectSession returns the OIDC session for an authorization code.
func (s *MemoryStorage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.oidcSessions[hashSignature(authorizeCode)]
	if !ok {
		return nil, openid.ErrNoSessionFound
	}
	return req, nil
}

// DeleteOpenIDConnectSession removes the OIDC session for an authorization code.
func (s *MemoryStorage) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.oidcSessions, hashSignature(authorizeCode))
	return nil
}

// --- Client Assertion JWT ---

// ClientAssertionJWTValid returns an error if the JTI is known or the DB check failed.
func (s *MemoryStorage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	// For in-memory storage, we don't track JTIs
	// In production, this would check if the JTI has been used
	return nil
}

// SetClientAssertionJWT marks a JTI as used.
func (s *MemoryStorage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	// For in-memory storage, we don't track JTIs
	// In production, this would store the JTI with its expiration
	return nil
}

// --- Cleanup ---

// CleanupExpired removes all expired entries.
// Should be called periodically (e.g., every minute).
func (s *MemoryStorage) CleanupExpired(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Clean up auth codes
	for sig, stored := range s.authCodes {
		if now.After(stored.expiresAt) {
			delete(s.authCodes, sig)
		}
	}

	// Clean up access tokens
	for sig, stored := range s.accessTokens {
		if now.After(stored.expiresAt) {
			delete(s.accessTokens, sig)
		}
	}

	// Clean up refresh tokens
	for sig, stored := range s.refreshTokens {
		if !stored.expiresAt.IsZero() && now.After(stored.expiresAt) {
			delete(s.refreshTokens, sig)
		}
	}

	// Clean up PKCE sessions
	for sig, stored := range s.pkceSessions {
		if now.After(stored.expiresAt) {
			delete(s.pkceSessions, sig)
		}
	}

	return nil
}

// --- User Storage for Federation ---

// CreateUser creates a new user.
func (s *MemoryStorage) CreateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.ID]; exists {
		return ErrUserExists
	}

	s.users[user.ID] = user
	return nil
}

// GetUserByID retrieves a user by ID.
func (s *MemoryStorage) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// GetUserByEmail retrieves a user by email.
func (s *MemoryStorage) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, ErrUserNotFound
}

// GetUserByFederationID retrieves a user by their federation ID.
func (s *MemoryStorage) GetUserByFederationID(ctx context.Context, federationID uuid.UUID) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.FederationID != nil && *user.FederationID == federationID {
			return user, nil
		}
	}
	return nil, ErrUserNotFound
}

// UpdateUser updates an existing user.
func (s *MemoryStorage) UpdateUser(ctx context.Context, user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.ID]; !exists {
		return ErrUserNotFound
	}

	s.users[user.ID] = user
	return nil
}

// DeleteUser deletes a user.
func (s *MemoryStorage) DeleteUser(ctx context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[id]; !exists {
		return ErrUserNotFound
	}

	delete(s.users, id)
	return nil
}

// Ensure MemoryStorage implements Storage.
var (
	_ Storage             = (*MemoryStorage)(nil)
	_ SubjectTokenRevoker = (*MemoryStorage)(nil)
)
