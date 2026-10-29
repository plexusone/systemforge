package systemauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/ory/fosite/handler/openid"
	"github.com/plexusone/systemforge/identity/clientassertion"
)

// MemoryStorage implements the Storage interface using in-memory maps.
// This is suitable for embedded mode and testing.
type MemoryStorage struct {
	mu sync.RWMutex

	// jtis records used client-assertion JWT IDs.
	jtis *clientassertion.MemoryJTIStore

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

	// Human principals and their linked external identities
	humans   map[uuid.UUID]*HumanPrincipal
	external map[string]uuid.UUID // externalKey(provider, subject) -> principal ID
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
		jtis:          clientassertion.NewMemoryJTIStore(),
		clients:       make(map[string]*Client),
		authCodes:     make(map[string]*storedAuthCode),
		accessTokens:  make(map[string]*storedToken),
		refreshTokens: make(map[string]*storedToken),
		pkceSessions:  make(map[string]*storedAuthCode),
		oidcSessions:  make(map[string]fosite.Requester),
		humans:        make(map[uuid.UUID]*HumanPrincipal),
		external:      make(map[string]uuid.UUID),
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
	if err := validateClientMetadata(client); err != nil {
		return err
	}
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
	if err := validateClientMetadata(client); err != nil {
		return err
	}
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
		// Fosite needs the request to revoke the tokens issued from a
		// replayed code.
		return stored.request, fosite.ErrInvalidatedAuthorizeCode
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
	stored, ok := s.authCodes[sig]
	if !ok {
		return fosite.ErrNotFound
	}
	if stored.used {
		// Another exchange of this code already won.
		return fosite.ErrInvalidatedAuthorizeCode
	}
	stored.used = true
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

	// Only an active presented token rotates, so of two concurrent refreshes
	// with the same token only one succeeds.
	presented, ok := s.refreshTokens[hashSignature(refreshTokenSignature)]
	if !ok || presented.revoked {
		return fosite.ErrInactiveToken
	}

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

// ClientAssertionJWTValid returns fosite.ErrJTIKnown if the JTI was used
// and has not expired, so a captured client assertion cannot be replayed.
func (s *MemoryStorage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return s.jtis.Valid(ctx, jti)
}

// SetClientAssertionJWT marks a JTI as used until exp.
func (s *MemoryStorage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return s.jtis.Mark(ctx, jti, exp)
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

// --- Human Principal Storage ---

func copyHuman(h *HumanPrincipal) *HumanPrincipal {
	cp := *h
	if h.Metadata != nil {
		cp.Metadata = make(map[string]any, len(h.Metadata))
		for k, v := range h.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}

// humanByEmailLocked returns the human with the given email, ignoring case.
// The caller must hold s.mu.
func (s *MemoryStorage) humanByEmailLocked(email string) (*HumanPrincipal, bool) {
	if email == "" {
		// A human without an email (a managed principal) is never found
		// by email.
		return nil, false
	}
	for _, h := range s.humans {
		if h.Email != "" && strings.EqualFold(h.Email, email) {
			return h, true
		}
	}
	return nil, false
}

// CreateHuman implements Storage.
func (s *MemoryStorage) CreateHuman(_ context.Context, h *HumanPrincipal) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if h.Email == "" {
		return ErrEmailRequired
	}
	if h.ID == uuid.Nil {
		h.ID = uuid.New()
	}
	if _, exists := s.humans[h.ID]; exists {
		return ErrPrincipalExists
	}
	if _, exists := s.humanByEmailLocked(h.Email); exists {
		return ErrPrincipalExists
	}
	now := time.Now()
	stored := copyHuman(h)
	stored.CreatedAt, stored.UpdatedAt = now, now
	s.humans[h.ID] = stored
	return nil
}

// GetHuman implements Storage.
func (s *MemoryStorage) GetHuman(_ context.Context, id uuid.UUID) (*HumanPrincipal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	h, ok := s.humans[id]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	return copyHuman(h), nil
}

// GetHumanByEmail implements Storage. The match is case-insensitive.
func (s *MemoryStorage) GetHumanByEmail(_ context.Context, email string) (*HumanPrincipal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	h, ok := s.humanByEmailLocked(email)
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	return copyHuman(h), nil
}

// GetHumanByExternalIdentity implements Storage.
func (s *MemoryStorage) GetHumanByExternalIdentity(_ context.Context, provider, subject string) (*HumanPrincipal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.external[externalKey(provider, subject)]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	h, ok := s.humans[id]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	return copyHuman(h), nil
}

// LinkExternalIdentity implements Storage.
func (s *MemoryStorage) LinkExternalIdentity(_ context.Context, principalID uuid.UUID, provider, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := externalKey(provider, subject)
	if existing, ok := s.external[key]; ok {
		if existing == principalID {
			return nil
		}
		return ErrExternalIdentityExists
	}
	if _, ok := s.humans[principalID]; !ok {
		return ErrPrincipalNotFound
	}
	s.external[key] = principalID
	return nil
}

// UpdateHuman implements Storage.
func (s *MemoryStorage) UpdateHuman(_ context.Context, h *HumanPrincipal) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.humans[h.ID]
	if !ok {
		return ErrPrincipalNotFound
	}
	if other, taken := s.humanByEmailLocked(h.Email); taken && other.ID != h.ID {
		return ErrPrincipalExists
	}
	stored := copyHuman(h)
	if !strings.EqualFold(current.Email, h.Email) {
		// A new address is unverified until it is proven.
		stored.EmailVerified = false
	}
	stored.CreatedAt = current.CreatedAt
	stored.UpdatedAt = time.Now()
	s.humans[h.ID] = stored
	return nil
}

// DeleteHuman implements Storage. It also removes the human's external
// identities.
func (s *MemoryStorage) DeleteHuman(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.humans[id]; !ok {
		return ErrPrincipalNotFound
	}
	delete(s.humans, id)
	for key, pid := range s.external {
		if pid == id {
			delete(s.external, key)
		}
	}
	return nil
}

// Ensure MemoryStorage implements Storage.
var (
	_ Storage             = (*MemoryStorage)(nil)
	_ SubjectTokenRevoker = (*MemoryStorage)(nil)
)
