// Package apikey provides API key generation, validation, and management.
// API keys are used for server-to-server authentication without user interaction.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// base62Alphabet is the character set for base62 encoding (alphanumeric only).
// This avoids underscores which are used as key delimiters.
const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Common errors.
var (
	ErrInvalidKey      = errors.New("invalid API key")
	ErrKeyNotFound     = errors.New("API key not found")
	ErrKeyExpired      = errors.New("API key expired")
	ErrKeyRevoked      = errors.New("API key revoked")
	ErrInvalidScope    = errors.New("invalid scope")
	ErrScopeNotAllowed = errors.New("scope not allowed")
)

// Environment represents the API key environment.
type Environment string

const (
	// EnvLive is for production API keys.
	EnvLive Environment = "live"
	// EnvTest is for test/development API keys.
	EnvTest Environment = "test"
)

// KeyFormat defines the format of generated API keys.
// Format: {prefix}_{environment}_{random}
// Example: sf_live_abc123def456...
const (
	// DefaultPrefix is the default key prefix.
	DefaultPrefix = "sf"
	// KeyRandomBytes is the number of random bytes in the key.
	KeyRandomBytes = 32
	// PrefixRandomBytes is the number of random bytes in the visible prefix.
	PrefixRandomBytes = 8
)

// APIKey represents an API key with its metadata.
type APIKey struct {
	// ID is the unique identifier.
	ID uuid.UUID `json:"id"`

	// Name is a human-readable name.
	Name string `json:"name"`

	// Prefix is the visible portion of the key.
	Prefix string `json:"prefix"`

	// OwnerID is the user who owns this key.
	OwnerID uuid.UUID `json:"owner_id"`

	// OrganizationID is the org this key is scoped to (optional).
	OrganizationID *uuid.UUID `json:"organization_id,omitempty"`

	// Scopes are the permissions granted to this key.
	Scopes []string `json:"scopes,omitempty"`

	// Description is an optional note.
	Description string `json:"description,omitempty"`

	// Environment is live or test.
	Environment Environment `json:"environment"`

	// ExpiresAt is when the key expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// LastUsedAt is when the key was last used.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`

	// LastUsedIP is the IP that last used the key.
	LastUsedIP string `json:"last_used_ip,omitempty"`

	// Revoked indicates if the key is revoked.
	Revoked bool `json:"revoked"`

	// RevokedAt is when the key was revoked.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`

	// RevokedReason is why the key was revoked.
	RevokedReason string `json:"revoked_reason,omitempty"`

	// Metadata is additional key-value data.
	Metadata map[string]string `json:"metadata,omitempty"`

	// CreatedAt is when the key was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the key was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// IsExpired returns true if the key has expired.
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// IsValid returns true if the key is valid (not expired, not revoked).
func (k *APIKey) IsValid() bool {
	return !k.Revoked && !k.IsExpired()
}

// HasScope returns true if the key has the given scope.
func (k *APIKey) HasScope(scope string) bool {
	for _, s := range k.Scopes {
		if s == scope || s == "*" {
			return true
		}
		// Check wildcard patterns like "read:*"
		if strings.HasSuffix(s, ":*") {
			prefix := strings.TrimSuffix(s, "*")
			if strings.HasPrefix(scope, prefix) {
				return true
			}
		}
	}
	return false
}

// HasAnyScope returns true if the key has any of the given scopes.
func (k *APIKey) HasAnyScope(scopes ...string) bool {
	return slices.ContainsFunc(scopes, k.HasScope)
}

// HasAllScopes returns true if the key has all of the given scopes.
func (k *APIKey) HasAllScopes(scopes ...string) bool {
	for _, scope := range scopes {
		if !k.HasScope(scope) {
			return false
		}
	}
	return true
}

// GeneratedKey contains a newly created API key with its full value.
// The full key is only available at creation time.
type GeneratedKey struct {
	// Key is the full API key value (only shown once).
	Key string `json:"key"`

	// APIKey is the key metadata.
	APIKey *APIKey `json:"api_key"`
}

// CreateKeyRequest contains parameters for creating an API key.
type CreateKeyRequest struct {
	// Name is a human-readable name (required).
	Name string

	// OwnerID is the user creating the key (required).
	OwnerID uuid.UUID

	// OrganizationID scopes the key to an organization (optional).
	OrganizationID *uuid.UUID

	// Scopes are the permissions to grant (optional).
	Scopes []string

	// Description is an optional note.
	Description string

	// Environment is live or test (default: live).
	Environment Environment

	// ExpiresIn is the key lifetime (optional, nil = never).
	ExpiresIn *time.Duration

	// Metadata is additional key-value data.
	Metadata map[string]string
}

// Store defines the interface for API key storage.
//
//nolint:dupl // Store and EntClientInterface are intentionally similar but serve different purposes
type Store interface {
	// Create stores a new API key.
	Create(ctx context.Context, key *APIKey, keyHash string) error

	// GetByPrefix retrieves a key by its prefix.
	GetByPrefix(ctx context.Context, prefix string) (*APIKey, string, error)

	// GetByID retrieves a key by its ID.
	GetByID(ctx context.Context, id uuid.UUID) (*APIKey, error)

	// ListByOwner lists all keys for a user.
	ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]*APIKey, error)

	// ListByOrganization lists all keys for an organization.
	ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*APIKey, error)

	// Update updates key metadata.
	Update(ctx context.Context, key *APIKey) error

	// Delete permanently removes a key.
	Delete(ctx context.Context, id uuid.UUID) error

	// UpdateLastUsed updates the last used timestamp and IP.
	UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error
}

// ServiceConfig contains configuration for the API key service.
type ServiceConfig struct {
	// Store is the key storage backend.
	Store Store

	// Prefix is the key prefix (default: "sf").
	Prefix string

	// AllowedScopes restricts which scopes can be granted.
	// If empty, any scope is allowed.
	AllowedScopes []string

	// MaxKeysPerUser limits keys per user (0 = unlimited).
	MaxKeysPerUser int

	// DefaultExpiry is the default key lifetime.
	DefaultExpiry *time.Duration
}

// Service provides API key management operations.
type Service struct {
	config        ServiceConfig
	allowedScopes map[string]bool
}

// NewService creates a new API key service.
func NewService(config ServiceConfig) *Service {
	if config.Prefix == "" {
		config.Prefix = DefaultPrefix
	}

	allowedScopes := make(map[string]bool)
	for _, s := range config.AllowedScopes {
		allowedScopes[s] = true
	}

	return &Service{
		config:        config,
		allowedScopes: allowedScopes,
	}
}

// Create generates a new API key.
// The full key is only returned once and cannot be retrieved later.
func (s *Service) Create(ctx context.Context, req CreateKeyRequest) (*GeneratedKey, error) {
	// Validate request
	if req.Name == "" {
		return nil, errors.New("name is required")
	}
	if req.OwnerID == uuid.Nil {
		return nil, errors.New("owner_id is required")
	}

	// Validate scopes
	if len(s.allowedScopes) > 0 {
		for _, scope := range req.Scopes {
			if !s.isAllowedScope(scope) {
				return nil, fmt.Errorf("%w: %s", ErrScopeNotAllowed, scope)
			}
		}
	}

	// Set defaults
	env := req.Environment
	if env == "" {
		env = EnvLive
	}

	// Generate the key
	fullKey, prefix, keyHash, err := s.generateKey(env)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	// Calculate expiry
	var expiresAt *time.Time
	if req.ExpiresIn != nil {
		t := time.Now().Add(*req.ExpiresIn)
		expiresAt = &t
	} else if s.config.DefaultExpiry != nil {
		t := time.Now().Add(*s.config.DefaultExpiry)
		expiresAt = &t
	}

	now := time.Now()
	apiKey := &APIKey{
		ID:             uuid.New(),
		Name:           req.Name,
		Prefix:         prefix,
		OwnerID:        req.OwnerID,
		OrganizationID: req.OrganizationID,
		Scopes:         req.Scopes,
		Description:    req.Description,
		Environment:    env,
		ExpiresAt:      expiresAt,
		Metadata:       req.Metadata,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	// Store the key
	if err := s.config.Store.Create(ctx, apiKey, keyHash); err != nil {
		return nil, fmt.Errorf("store key: %w", err)
	}

	return &GeneratedKey{
		Key:    fullKey,
		APIKey: apiKey,
	}, nil
}

// Validate validates an API key and returns its metadata.
func (s *Service) Validate(ctx context.Context, key string) (*APIKey, error) {
	// Parse the key
	prefix, err := s.parseKeyPrefix(key)
	if err != nil {
		return nil, ErrInvalidKey
	}

	// Look up by prefix
	apiKey, storedHash, err := s.config.Store.GetByPrefix(ctx, prefix)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return nil, ErrInvalidKey
		}
		return nil, err
	}

	// Verify the hash
	keyHash := s.hashKey(key)
	if keyHash != storedHash {
		return nil, ErrInvalidKey
	}

	// Check if revoked
	if apiKey.Revoked {
		return nil, ErrKeyRevoked
	}

	// Check if expired
	if apiKey.IsExpired() {
		return nil, ErrKeyExpired
	}

	return apiKey, nil
}

// ValidateWithScope validates a key and checks for a required scope.
func (s *Service) ValidateWithScope(ctx context.Context, key, scope string) (*APIKey, error) {
	apiKey, err := s.Validate(ctx, key)
	if err != nil {
		return nil, err
	}

	if !apiKey.HasScope(scope) {
		return nil, ErrScopeNotAllowed
	}

	return apiKey, nil
}

// Get retrieves a key by ID.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*APIKey, error) {
	return s.config.Store.GetByID(ctx, id)
}

// List retrieves all keys for a user.
func (s *Service) List(ctx context.Context, ownerID uuid.UUID) ([]*APIKey, error) {
	return s.config.Store.ListByOwner(ctx, ownerID)
}

// ListByOrganization retrieves all keys for an organization.
func (s *Service) ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*APIKey, error) {
	return s.config.Store.ListByOrganization(ctx, orgID)
}

// Revoke revokes an API key.
func (s *Service) Revoke(ctx context.Context, id uuid.UUID, reason string) error {
	apiKey, err := s.config.Store.GetByID(ctx, id)
	if err != nil {
		return err
	}

	now := time.Now()
	apiKey.Revoked = true
	apiKey.RevokedAt = &now
	apiKey.RevokedReason = reason
	apiKey.UpdatedAt = now

	return s.config.Store.Update(ctx, apiKey)
}

// Delete permanently removes an API key.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) error {
	return s.config.Store.Delete(ctx, id)
}

// RecordUsage updates the last used timestamp and IP.
func (s *Service) RecordUsage(ctx context.Context, id uuid.UUID, ip string) error {
	return s.config.Store.UpdateLastUsed(ctx, id, ip)
}

// generateKey generates a new API key with prefix and hash.
func (s *Service) generateKey(env Environment) (fullKey, prefix, keyHash string, err error) {
	// Generate random bytes for the key
	keyBytes := make([]byte, KeyRandomBytes)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", "", err
	}

	// Generate random bytes for the prefix
	prefixBytes := make([]byte, PrefixRandomBytes)
	if _, err := rand.Read(prefixBytes); err != nil {
		return "", "", "", err
	}

	// Build the prefix: sf_live_abc123...
	// Use base62 encoding to avoid underscores in the random part
	prefixRandom := encodeBase62(prefixBytes)
	prefix = fmt.Sprintf("%s_%s_%s", s.config.Prefix, env, prefixRandom)

	// Build the full key: prefix + base62(random)
	keyRandom := encodeBase62(keyBytes)
	fullKey = prefix + "_" + keyRandom

	// Hash the full key for storage
	keyHash = s.hashKey(fullKey)

	return fullKey, prefix, keyHash, nil
}

// encodeBase62 encodes bytes to a base62 string (alphanumeric only).
// This is similar to Bitcoin's base58 but uses all alphanumeric characters.
func encodeBase62(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// Convert bytes to a big integer
	num := new(big.Int).SetBytes(data)
	base := big.NewInt(62)
	zero := big.NewInt(0)
	mod := new(big.Int)

	// Build the encoded string
	var result []byte
	for num.Cmp(zero) > 0 {
		num.DivMod(num, base, mod)
		result = append(result, base62Alphabet[mod.Int64()])
	}

	// Add leading zeros for any leading zero bytes in input
	for _, b := range data {
		if b != 0 {
			break
		}
		result = append(result, base62Alphabet[0])
	}

	// Reverse the result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// hashKey computes the SHA-256 hash of a key.
func (s *Service) hashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// parseKeyPrefix extracts the prefix from a full key.
func (s *Service) parseKeyPrefix(key string) (string, error) {
	// Key format: sf_live_abc123..._randomdata
	// Prefix format: sf_live_abc123...
	parts := strings.Split(key, "_")
	if len(parts) < 4 {
		return "", ErrInvalidKey
	}

	// Reconstruct prefix (first 3 parts)
	prefix := strings.Join(parts[:3], "_")
	return prefix, nil
}

// isAllowedScope checks if a scope is in the allowed list.
func (s *Service) isAllowedScope(scope string) bool {
	if len(s.allowedScopes) == 0 {
		return true
	}

	// Check exact match
	if s.allowedScopes[scope] {
		return true
	}

	// Check wildcard patterns
	for allowed := range s.allowedScopes {
		if strings.HasSuffix(allowed, ":*") {
			prefix := strings.TrimSuffix(allowed, "*")
			if strings.HasPrefix(scope, prefix) {
				return true
			}
		}
	}

	return false
}

// ParseEnvironment parses an environment string.
func ParseEnvironment(s string) (Environment, error) {
	switch strings.ToLower(s) {
	case "live", "production", "prod":
		return EnvLive, nil
	case "test", "development", "dev", "staging":
		return EnvTest, nil
	default:
		return "", fmt.Errorf("invalid environment: %s", s)
	}
}
