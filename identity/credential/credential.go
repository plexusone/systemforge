// Package credential provides credential management for principals.
// Credentials can be passwords, API keys, keypairs, WebAuthn credentials, or TOTP secrets.
package credential

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Type represents the type of credential.
type Type string

const (
	// TypePassword represents a password credential.
	TypePassword Type = "password"
	// TypeAPIKey represents an API key credential.
	TypeAPIKey Type = "api_key"
	// TypeKeypair represents a public/private keypair credential.
	TypeKeypair Type = "keypair"
	// TypeWebAuthn represents a WebAuthn credential.
	TypeWebAuthn Type = "webauthn"
	// TypeTOTP represents a TOTP credential.
	TypeTOTP Type = "totp"
	// TypeClientSecret represents an OAuth client secret.
	TypeClientSecret Type = "client_secret"
)

// Credential represents a credential record.
type Credential struct {
	ID            uuid.UUID      `json:"id"`
	PrincipalID   uuid.UUID      `json:"principal_id"`
	Type          Type           `json:"type"`
	Identifier    string         `json:"identifier,omitempty"` // e.g., key prefix for API keys
	Name          string         `json:"name,omitempty"`
	Scopes        []string       `json:"scopes,omitempty"`
	Active        bool           `json:"active"`
	ExpiresAt     *time.Time     `json:"expires_at,omitempty"`
	Revoked       bool           `json:"revoked"`
	RevokedAt     *time.Time     `json:"revoked_at,omitempty"`
	RevokedReason string         `json:"revoked_reason,omitempty"`
	LastUsedAt    *time.Time     `json:"last_used_at,omitempty"`
	LastUsedIP    string         `json:"last_used_ip,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// GeneratedAPIKey contains a newly generated API key.
// The PlainKey is only available at creation time.
type GeneratedAPIKey struct {
	Credential *Credential `json:"credential"`
	PlainKey   string      `json:"plain_key"` // Only available at creation time
	Prefix     string      `json:"prefix"`    // First 8 chars for identification
}

// GeneratedClientSecret contains a newly generated client secret.
type GeneratedClientSecret struct {
	Credential  *Credential `json:"credential"`
	PlainSecret string      `json:"plain_secret"` // Only available at creation time
	Prefix      string      `json:"prefix"`       // First 8 chars for identification
}

// KeypairCredential contains keypair-specific data.
type KeypairCredential struct {
	Credential   *Credential `json:"credential"`
	KeyID        string      `json:"key_id"`        // Used in JWT kid header
	KeyAlgorithm string      `json:"key_algorithm"` // RS256, ES256, etc.
	PublicKeyPEM string      `json:"public_key_pem"`
}

// CreatePasswordInput contains fields for creating a password credential.
type CreatePasswordInput struct {
	PrincipalID uuid.UUID
	Password    string `json:"-"` //nolint:gosec // G117: field holds user-provided value, not a hardcoded secret
}

// CreateAPIKeyInput contains fields for creating an API key credential.
type CreateAPIKeyInput struct {
	PrincipalID uuid.UUID
	Name        string
	Scopes      []string
	ExpiresAt   *time.Time
	Metadata    map[string]any
}

// CreateClientSecretInput contains fields for creating a client secret.
type CreateClientSecretInput struct {
	PrincipalID uuid.UUID
	Name        string
	ExpiresAt   *time.Time
	Metadata    map[string]any
}

// CreateKeypairInput contains fields for creating a keypair credential.
type CreateKeypairInput struct {
	PrincipalID  uuid.UUID
	Name         string
	KeyAlgorithm string // RS256, ES256, EdDSA
	PublicKeyPEM string
	Scopes       []string
	ExpiresAt    *time.Time
	Metadata     map[string]any
}

// Service defines the business logic interface for credentials.
type Service interface {
	// Password operations
	CreatePassword(ctx context.Context, input CreatePasswordInput) error
	VerifyPassword(ctx context.Context, principalID uuid.UUID, password string) (bool, error)
	UpdatePassword(ctx context.Context, principalID uuid.UUID, newPassword string) error

	// API key operations
	CreateAPIKey(ctx context.Context, input CreateAPIKeyInput) (*GeneratedAPIKey, error)
	ValidateAPIKey(ctx context.Context, plainKey string) (*Credential, error)
	ListAPIKeys(ctx context.Context, principalID uuid.UUID) ([]*Credential, error)

	// Client secret operations
	CreateClientSecret(ctx context.Context, input CreateClientSecretInput) (*GeneratedClientSecret, error)
	ValidateClientSecret(ctx context.Context, clientID, plainSecret string) (*Credential, error)

	// Keypair operations
	CreateKeypair(ctx context.Context, input CreateKeypairInput) (*KeypairCredential, error)
	GetKeypairByKeyID(ctx context.Context, keyID string) (*KeypairCredential, error)
	ListKeypairs(ctx context.Context, principalID uuid.UUID) ([]*KeypairCredential, error)

	// Common operations
	GetByID(ctx context.Context, id uuid.UUID) (*Credential, error)
	Revoke(ctx context.Context, id uuid.UUID, reason string) error
	UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error
}
