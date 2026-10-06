package systemauth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
)

// Storage defines the persistence interface for SystemAuth.
// It extends Fosite's storage requirements with client management.
type Storage interface {
	// Fosite storage interfaces
	fosite.ClientManager

	// Authorization code operations
	CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error
	GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error)
	InvalidateAuthorizeCodeSession(ctx context.Context, code string) error

	// Access token operations
	CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error
	GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
	DeleteAccessTokenSession(ctx context.Context, signature string) error

	// Refresh token operations
	CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error
	GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
	DeleteRefreshTokenSession(ctx context.Context, signature string) error
	RevokeRefreshToken(ctx context.Context, requestID string) error
	RevokeAccessToken(ctx context.Context, requestID string) error
	RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error

	// PKCE operations
	CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error
	GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
	DeletePKCERequestSession(ctx context.Context, signature string) error

	// Client assertion JWT tracking
	ClientAssertionJWTValid(ctx context.Context, jti string) error
	SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error

	// Client management operations (extended)
	CreateClient(ctx context.Context, client *Client) error
	GetClientByID(ctx context.Context, id string) (*Client, error)
	UpdateClient(ctx context.Context, client *Client) error
	DeleteClient(ctx context.Context, id string) error
	ListClients(ctx context.Context) ([]*Client, error)

	// User management for federation (optional - may return ErrNotImplemented)
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByFederationID(ctx context.Context, federationID uuid.UUID) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
}

// SubjectTokenRevoker is implemented by storage that can revoke every
// access and refresh token issued to a subject (principal). SystemAuth uses
// it on logout to end the principal's delegated access along with the login
// session. MemoryStorage and EntStorage implement it.
type SubjectTokenRevoker interface {
	// RevokeSubjectTokens marks all of subject's access and refresh tokens
	// revoked. Revoking a subject without tokens is not an error.
	RevokeSubjectTokens(ctx context.Context, subject string) error
}

// StoredRequest holds the data needed to reconstruct a fosite.Requester.
type StoredRequest struct {
	ID            string
	ClientID      string
	Scopes        []string
	GrantedScopes []string
	Form          map[string][]string
	Session       *StoredSession
	RequestedAt   time.Time
}

// ClientManager provides CRUD operations for OAuth clients.
type ClientManager interface {
	// CreateClient creates a new OAuth client.
	CreateClient(ctx context.Context, client *Client) error

	// GetClientByID retrieves a client by ID.
	GetClientByID(ctx context.Context, id string) (*Client, error)

	// UpdateClient updates an existing client.
	UpdateClient(ctx context.Context, client *Client) error

	// DeleteClient deletes a client.
	DeleteClient(ctx context.Context, id string) error

	// ListClients returns all clients.
	ListClients(ctx context.Context) ([]*Client, error)
}

// StoredSession holds serializable session information.
type StoredSession struct {
	// Subject is the user ID.
	Subject string `json:"sub"`

	// Username is the human-readable username.
	Username string `json:"username,omitempty"`

	// Email is the user's email.
	Email string `json:"email,omitempty"`

	// Claims are additional claims.
	Claims map[string]any `json:"claims,omitempty"`

	// ExpiresAt maps token types to expiration times (unix timestamps).
	ExpiresAt map[string]int64 `json:"expires_at"`

	// RequestedAt is when the session was created (unix timestamp).
	RequestedAt int64 `json:"requested_at"`
}

// AuthCodeData holds authorization code storage data.
type AuthCodeData struct {
	// Signature is the hashed authorization code.
	Signature string

	// ClientID is the client that requested the code.
	ClientID string

	// Subject is the user ID.
	Subject string

	// RedirectURI is the callback URI.
	RedirectURI string

	// Scopes are the requested scopes.
	Scopes []string

	// GrantedScopes are the granted scopes.
	GrantedScopes []string

	// State is the CSRF state parameter.
	State string

	// CodeChallenge is the PKCE code challenge.
	CodeChallenge string

	// CodeChallengeMethod is the PKCE method (S256 or plain).
	CodeChallengeMethod string

	// Nonce is the OpenID Connect nonce.
	Nonce string

	// Session holds the session data.
	Session *StoredSession

	// ExpiresAt is when the code expires.
	ExpiresAt int64

	// Used indicates the code has been exchanged.
	Used bool
}

// TokenData holds access/refresh token storage data.
type TokenData struct {
	// AccessTokenSignature is the hashed access token.
	AccessTokenSignature string

	// RefreshTokenSignature is the hashed refresh token.
	RefreshTokenSignature string

	// ClientID is the client that owns the token.
	ClientID string

	// Subject is the user ID.
	Subject string

	// Scopes are the granted scopes.
	Scopes []string

	// Session holds the session data.
	Session *StoredSession

	// AccessExpiresAt is when the access token expires.
	AccessExpiresAt int64

	// RefreshExpiresAt is when the refresh token expires.
	RefreshExpiresAt int64

	// Revoked indicates the token has been revoked.
	Revoked bool

	// RequestID is used for token family tracking.
	RequestID string
}
