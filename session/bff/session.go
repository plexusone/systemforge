// Package bff implements the Backend for Frontend (BFF) pattern for secure
// session management. The BFF holds tokens server-side and uses HTTP-only
// cookies to identify browser sessions.
package bff

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/grokify/goauth/dpop"
)

// Session represents a server-side session with stored tokens and DPoP keys.
//
//nolint:gosec // G117: struct fields hold runtime OAuth tokens, not hardcoded secrets
type Session struct {
	// ID is the unique session identifier.
	ID string `json:"id"`

	// UserID is the authenticated user's ID.
	UserID uuid.UUID `json:"user_id"`

	// OrganizationID is the current organization context (optional).
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`

	// AccessToken is the OAuth access token.
	AccessToken string `json:"access_token"`

	// RefreshToken is the OAuth refresh token.
	RefreshToken string `json:"refresh_token"`

	// TokenType is the token_type the token endpoint returned with
	// AccessToken: "DPoP" for a token bound to the session's DPoP key,
	// which the proxy presents with the DPoP scheme and a proof, or
	// "Bearer" for an unbound token, presented as Bearer.
	TokenType string `json:"token_type,omitempty"`

	// AccessTokenExpiresAt is when the access token expires.
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at"`

	// RefreshTokenExpiresAt is when the refresh token expires.
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`

	// DPoPKeyPairJSON is the serialized DPoP key pair for this session.
	// The BFF uses this to sign DPoP proofs when proxying requests to the API.
	DPoPKeyPairJSON []byte `json:"dpop_key_pair,omitempty"`

	// DPoPThumbprint is the JWK thumbprint of the DPoP key pair.
	DPoPThumbprint string `json:"dpop_thumbprint,omitempty"`

	// Metadata contains optional session metadata.
	Metadata map[string]string `json:"metadata,omitempty"`

	// CreatedAt is when the session was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the session was last updated.
	UpdatedAt time.Time `json:"updated_at"`

	// LastAccessedAt is when the session was last accessed.
	LastAccessedAt time.Time `json:"last_accessed_at"`

	// ExpiresAt is when the session expires (based on refresh token or absolute timeout).
	ExpiresAt time.Time `json:"expires_at"`

	// IPAddress is the IP address that created the session.
	IPAddress string `json:"ip_address,omitempty"`

	// UserAgent is the user agent that created the session.
	UserAgent string `json:"user_agent,omitempty"`

	// Internal fields for encrypted storage (not serialized to JSON)
	// These are used by EntStore to pass encrypted data to the client wrapper.
	encryptedAccessToken  []byte `json:"-"`
	encryptedRefreshToken []byte `json:"-"`
	encryptedDPoPKeyPair  []byte `json:"-"`
}

// IsExpired returns true if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsAccessTokenExpired returns true if the access token has expired.
func (s *Session) IsAccessTokenExpired() bool {
	return time.Now().After(s.AccessTokenExpiresAt)
}

// IsRefreshTokenExpired returns true if the refresh token has expired.
func (s *Session) IsRefreshTokenExpired() bool {
	return time.Now().After(s.RefreshTokenExpiresAt)
}

// NeedsRefresh returns true if the access token needs to be refreshed.
// This returns true if the access token is expired or will expire soon.
func (s *Session) NeedsRefresh(threshold time.Duration) bool {
	return time.Now().Add(threshold).After(s.AccessTokenExpiresAt)
}

// Default session lifetime limits, applied when IdleTimeout or MaxLifetime
// is left zero in HandlerConfig or MiddlewareConfig.
const (
	// DefaultIdleTimeout ends a session that has not been used for a day.
	DefaultIdleTimeout = 24 * time.Hour

	// DefaultMaxLifetime ends a session a week after it was created, however
	// often its tokens are refreshed; the user must sign in again.
	DefaultMaxLifetime = 7 * 24 * time.Hour
)

// resolveLifetimeLimit returns def for a zero limit and 0 (unchecked) for a
// negative one.
func resolveLifetimeLimit(limit, def time.Duration) time.Duration {
	switch {
	case limit == 0:
		return def
	case limit < 0:
		return 0
	default:
		return limit
	}
}

// LifetimeExceeded reports whether, at now, the session has been idle for
// longer than idleTimeout (measured from LastAccessedAt, or CreatedAt if
// it was never accessed) or has existed for longer than maxLifetime
// (measured from CreatedAt). A non-positive limit is not checked. A session
// with no CreatedAt fails a maxLifetime check, since its age is unknown.
func (s *Session) LifetimeExceeded(now time.Time, idleTimeout, maxLifetime time.Duration) bool {
	if maxLifetime > 0 {
		if s.CreatedAt.IsZero() || now.After(s.CreatedAt.Add(maxLifetime)) {
			return true
		}
	}
	if idleTimeout > 0 {
		last := s.LastAccessedAt
		if last.IsZero() {
			last = s.CreatedAt
		}
		if last.IsZero() || now.After(last.Add(idleTimeout)) {
			return true
		}
	}
	return false
}

// capExpiry returns expiry, moved back to CreatedAt+maxLifetime if it is
// later. A non-positive maxLifetime leaves expiry unchanged.
func (s *Session) capExpiry(expiry time.Time, maxLifetime time.Duration) time.Time {
	if maxLifetime <= 0 || s.CreatedAt.IsZero() {
		return expiry
	}
	if limit := s.CreatedAt.Add(maxLifetime); expiry.After(limit) {
		return limit
	}
	return expiry
}

// UsesDPoP reports whether the session's access token was issued as a
// DPoP-bound token (token_type DPoP), so it must be presented with the
// DPoP scheme and a proof by the session's key.
func (s *Session) UsesDPoP() bool {
	return strings.EqualFold(s.TokenType, TokenTypeDPoP)
}

// Token types of the token endpoint (RFC 9449, RFC 6750).
const (
	TokenTypeDPoP   = "DPoP"
	TokenTypeBearer = "Bearer"
)

// normalizeTokenType returns the canonical spelling of a token_type.
func normalizeTokenType(t string) string {
	switch {
	case strings.EqualFold(t, TokenTypeDPoP):
		return TokenTypeDPoP
	case strings.EqualFold(t, TokenTypeBearer):
		return TokenTypeBearer
	}
	return t
}

// HasDPoP returns true if the session has a DPoP key pair.
func (s *Session) HasDPoP() bool {
	return len(s.DPoPKeyPairJSON) > 0 && s.DPoPThumbprint != ""
}

// ErrNoDPoPKeyPair is returned when the session has no DPoP key pair.
var ErrNoDPoPKeyPair = errors.New("session has no DPoP key pair")

// GetDPoPKeyPair deserializes and returns the session's DPoP key pair.
func (s *Session) GetDPoPKeyPair() (*dpop.KeyPair, error) {
	if !s.HasDPoP() {
		return nil, ErrNoDPoPKeyPair
	}
	return dpop.DeserializeKeyPairJSON(s.DPoPKeyPairJSON)
}

// SetDPoPKeyPair stores the DPoP key pair in the session.
func (s *Session) SetDPoPKeyPair(kp *dpop.KeyPair) error {
	if kp == nil {
		s.DPoPKeyPairJSON = nil
		s.DPoPThumbprint = ""
		return nil
	}

	serialized, err := kp.SerializeJSON()
	if err != nil {
		return err
	}

	s.DPoPKeyPairJSON = serialized
	s.DPoPThumbprint = kp.Thumbprint
	return nil
}

// MaxSessionIDLength is the longest session ID ValidSessionID accepts.
const MaxSessionIDLength = 256

// ValidSessionID reports whether id is a well-formed session ID: 1 to
// MaxSessionIDLength characters from the URL-safe set A-Z, a-z, 0-9, '-',
// '_' and '.'. GenerateSessionID produces such IDs; a custom
// HandlerConfig.SessionIDGenerator must too. Session IDs arrive in client
// cookies, so other values are treated as no session rather than passed to
// the store.
func ValidSessionID(id string) bool {
	if id == "" || len(id) > MaxSessionIDLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return false
		}
	}
	return true
}

// SessionIDLength is the length of generated session IDs in bytes.
const SessionIDLength = 32

// GenerateSessionID generates a cryptographically secure session ID.
func GenerateSessionID() (string, error) {
	bytes := make([]byte, SessionIDLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// NewSession creates a new session with the given parameters.
func NewSession(userID uuid.UUID, accessToken, refreshToken string, accessExpiry, refreshExpiry time.Duration) (*Session, error) {
	id, err := GenerateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	return &Session{
		ID:                    id,
		UserID:                userID,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  now.Add(accessExpiry),
		RefreshTokenExpiresAt: now.Add(refreshExpiry),
		CreatedAt:             now,
		UpdatedAt:             now,
		LastAccessedAt:        now,
		ExpiresAt:             now.Add(refreshExpiry), // Session expires with refresh token
	}, nil
}

// EncryptedAccessToken returns the encrypted access token bytes.
// Used by Ent client wrappers to store encrypted tokens.
func (s *Session) EncryptedAccessToken() []byte {
	return s.encryptedAccessToken
}

// EncryptedRefreshToken returns the encrypted refresh token bytes.
// Used by Ent client wrappers to store encrypted tokens.
func (s *Session) EncryptedRefreshToken() []byte {
	return s.encryptedRefreshToken
}

// EncryptedDPoPKeyPair returns the encrypted DPoP key pair bytes.
// Used by Ent client wrappers to store encrypted tokens.
func (s *Session) EncryptedDPoPKeyPair() []byte {
	return s.encryptedDPoPKeyPair
}

// SetEncryptedTokens sets the encrypted token fields from database values.
// Used by Ent client wrappers when loading sessions from storage.
func (s *Session) SetEncryptedTokens(accessToken, refreshToken, dpopKeyPair []byte) {
	s.encryptedAccessToken = accessToken
	s.encryptedRefreshToken = refreshToken
	s.encryptedDPoPKeyPair = dpopKeyPair
}
