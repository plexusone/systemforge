package credential

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/identity"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/credential"
	"github.com/plexusone/systemforge/identity/ent/principal"
)

const (
	// APIKeyPrefix is the prefix for generated API keys.
	APIKeyPrefix = "sf_"
	// APIKeyBytes is the number of random bytes for API key generation.
	APIKeyBytes = 32
)

// DefaultService implements the Service interface.
type DefaultService struct {
	client *ent.Client
}

// NewService creates a new CredentialService.
func NewService(client *ent.Client) Service {
	return &DefaultService{client: client}
}

// CreatePassword creates a password credential for a principal.
func (s *DefaultService) CreatePassword(ctx context.Context, input CreatePasswordInput) error {
	// Hash the password using Argon2id
	hash, err := identity.HashPassword(input.Password, nil)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Check if principal already has a password credential
	existing, err := s.client.Credential.Query().
		Where(
			credential.PrincipalIDEQ(input.PrincipalID),
			credential.TypeEQ(credential.TypePassword),
			credential.ActiveEQ(true),
			credential.RevokedEQ(false),
		).
		First(ctx)

	if err == nil && existing != nil {
		// Update existing password
		_, err = s.client.Credential.UpdateOne(existing).
			SetSecretHash(hash).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("failed to update password: %w", err)
		}
		return nil
	}

	// Create new password credential
	_, err = s.client.Credential.Create().
		SetPrincipalID(input.PrincipalID).
		SetType(credential.TypePassword).
		SetSecretHash(hash).
		SetActive(true).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to create password credential: %w", err)
	}

	return nil
}

// VerifyPassword verifies a password against the stored hash.
func (s *DefaultService) VerifyPassword(ctx context.Context, principalID uuid.UUID, password string) (bool, error) {
	cred, err := s.client.Credential.Query().
		Where(
			credential.PrincipalIDEQ(principalID),
			credential.TypeEQ(credential.TypePassword),
			credential.ActiveEQ(true),
			credential.RevokedEQ(false),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to get password credential: %w", err)
	}

	if cred.SecretHash == "" {
		return false, nil
	}

	valid, err := identity.VerifyPassword(password, cred.SecretHash)
	if err != nil {
		return false, fmt.Errorf("failed to verify password: %w", err)
	}

	if valid {
		// Update last used
		now := time.Now()
		_, _ = s.client.Credential.UpdateOne(cred).
			SetLastUsedAt(now).
			Save(ctx)
	}

	return valid, nil
}

// UpdatePassword updates the password for a principal.
func (s *DefaultService) UpdatePassword(ctx context.Context, principalID uuid.UUID, newPassword string) error {
	return s.CreatePassword(ctx, CreatePasswordInput{
		PrincipalID: principalID,
		Password:    newPassword,
	})
}

// CreateAPIKey generates a new API key for a principal.
func (s *DefaultService) CreateAPIKey(ctx context.Context, input CreateAPIKeyInput) (*GeneratedAPIKey, error) {
	// Generate random bytes
	randomBytes := make([]byte, APIKeyBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Create the plain key
	plainKey := APIKeyPrefix + base64.RawURLEncoding.EncodeToString(randomBytes)
	prefix := plainKey[:12] // "sf_" + 8 chars

	// Hash the key for storage
	hash := sha256.Sum256([]byte(plainKey))
	keyHash := hex.EncodeToString(hash[:])

	// Create credential
	create := s.client.Credential.Create().
		SetPrincipalID(input.PrincipalID).
		SetType(credential.TypeAPIKey).
		SetIdentifier(prefix).
		SetSecretHash(keyHash).
		SetScopes(input.Scopes).
		SetActive(true)

	if input.Name != "" {
		create.SetName(input.Name)
	}
	if input.ExpiresAt != nil {
		create.SetExpiresAt(*input.ExpiresAt)
	}
	if input.Metadata != nil {
		create.SetMetadata(input.Metadata)
	}

	cred, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key credential: %w", err)
	}

	return &GeneratedAPIKey{
		Credential: entCredentialToModel(cred),
		PlainKey:   plainKey,
		Prefix:     prefix,
	}, nil
}

// ValidateAPIKey validates an API key and returns the associated credential.
func (s *DefaultService) ValidateAPIKey(ctx context.Context, plainKey string) (*Credential, error) {
	// Verify prefix
	if !strings.HasPrefix(plainKey, APIKeyPrefix) {
		return nil, fmt.Errorf("invalid API key format")
	}

	// Hash the key
	hash := sha256.Sum256([]byte(plainKey))
	keyHash := hex.EncodeToString(hash[:])

	// Look up by hash
	cred, err := s.client.Credential.Query().
		Where(
			credential.TypeEQ(credential.TypeAPIKey),
			credential.SecretHashEQ(keyHash),
			credential.ActiveEQ(true),
			credential.RevokedEQ(false),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("invalid API key")
		}
		return nil, fmt.Errorf("failed to validate API key: %w", err)
	}

	// Check expiration
	if cred.ExpiresAt != nil && cred.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("API key expired")
	}

	// Update last used
	now := time.Now()
	_, _ = s.client.Credential.UpdateOne(cred).
		SetLastUsedAt(now).
		Save(ctx)

	return entCredentialToModel(cred), nil
}

// ListAPIKeys lists all API keys for a principal.
func (s *DefaultService) ListAPIKeys(ctx context.Context, principalID uuid.UUID) ([]*Credential, error) {
	creds, err := s.client.Credential.Query().
		Where(
			credential.PrincipalIDEQ(principalID),
			credential.TypeEQ(credential.TypeAPIKey),
		).
		Order(ent.Desc(credential.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}

	result := make([]*Credential, len(creds))
	for i, c := range creds {
		result[i] = entCredentialToModel(c)
	}
	return result, nil
}

// CreateClientSecret generates a new client secret for an application principal.
func (s *DefaultService) CreateClientSecret(ctx context.Context, input CreateClientSecretInput) (*GeneratedClientSecret, error) {
	// Generate random bytes
	randomBytes := make([]byte, APIKeyBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Create the plain secret
	plainSecret := base64.RawURLEncoding.EncodeToString(randomBytes)
	prefix := plainSecret[:8]

	// Hash the secret for storage using Argon2id (like a password)
	secretHash, err := identity.HashPassword(plainSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to hash secret: %w", err)
	}

	// Create credential
	create := s.client.Credential.Create().
		SetPrincipalID(input.PrincipalID).
		SetType(credential.TypeClientSecret).
		SetIdentifier(prefix).
		SetSecretHash(secretHash).
		SetActive(true)

	if input.Name != "" {
		create.SetName(input.Name)
	}
	if input.ExpiresAt != nil {
		create.SetExpiresAt(*input.ExpiresAt)
	}
	if input.Metadata != nil {
		create.SetMetadata(input.Metadata)
	}

	cred, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create client secret credential: %w", err)
	}

	return &GeneratedClientSecret{
		Credential:  entCredentialToModel(cred),
		PlainSecret: plainSecret,
		Prefix:      prefix,
	}, nil
}

// ValidateClientSecret validates a client secret.
func (s *DefaultService) ValidateClientSecret(ctx context.Context, clientID, plainSecret string) (*Credential, error) {
	// Get the principal by client ID (identifier)
	p, err := s.client.Principal.Query().
		Where(
			principal.IdentifierEQ(clientID),
			principal.TypeEQ(principal.TypeApplication),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("invalid client ID")
		}
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}

	// Get all active client secrets for this principal
	creds, err := s.client.Credential.Query().
		Where(
			credential.PrincipalIDEQ(p.ID),
			credential.TypeEQ(credential.TypeClientSecret),
			credential.ActiveEQ(true),
			credential.RevokedEQ(false),
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get client secrets: %w", err)
	}

	// Try each secret
	for _, cred := range creds {
		// Check expiration
		if cred.ExpiresAt != nil && cred.ExpiresAt.Before(time.Now()) {
			continue
		}

		valid, err := identity.VerifyPassword(plainSecret, cred.SecretHash)
		if err != nil {
			continue
		}
		if valid {
			// Update last used
			now := time.Now()
			_, _ = s.client.Credential.UpdateOne(cred).
				SetLastUsedAt(now).
				Save(ctx)
			return entCredentialToModel(cred), nil
		}
	}

	return nil, fmt.Errorf("invalid client secret")
}

// CreateKeypair creates a keypair credential for a principal.
func (s *DefaultService) CreateKeypair(ctx context.Context, input CreateKeypairInput) (*KeypairCredential, error) {
	// Generate key ID
	keyID := uuid.New().String()

	// Create credential
	create := s.client.Credential.Create().
		SetPrincipalID(input.PrincipalID).
		SetType(credential.TypeKeypair).
		SetKeyID(keyID).
		SetKeyAlgorithm(input.KeyAlgorithm).
		SetPublicKey(input.PublicKeyPEM).
		SetScopes(input.Scopes).
		SetActive(true)

	if input.Name != "" {
		create.SetName(input.Name)
	}
	if input.ExpiresAt != nil {
		create.SetExpiresAt(*input.ExpiresAt)
	}
	if input.Metadata != nil {
		create.SetMetadata(input.Metadata)
	}

	cred, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create keypair credential: %w", err)
	}

	return &KeypairCredential{
		Credential:   entCredentialToModel(cred),
		KeyID:        keyID,
		KeyAlgorithm: input.KeyAlgorithm,
		PublicKeyPEM: input.PublicKeyPEM,
	}, nil
}

// GetKeypairByKeyID retrieves a keypair credential by key ID.
func (s *DefaultService) GetKeypairByKeyID(ctx context.Context, keyID string) (*KeypairCredential, error) {
	cred, err := s.client.Credential.Query().
		Where(
			credential.TypeEQ(credential.TypeKeypair),
			credential.KeyIDEQ(keyID),
			credential.ActiveEQ(true),
			credential.RevokedEQ(false),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("keypair not found: %s", keyID)
		}
		return nil, fmt.Errorf("failed to get keypair: %w", err)
	}

	// Check expiration
	if cred.ExpiresAt != nil && cred.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("keypair expired")
	}

	return &KeypairCredential{
		Credential:   entCredentialToModel(cred),
		KeyID:        derefStr(cred.KeyID),
		KeyAlgorithm: cred.KeyAlgorithm,
		PublicKeyPEM: cred.PublicKey,
	}, nil
}

// ListKeypairs lists all keypairs for a principal.
func (s *DefaultService) ListKeypairs(ctx context.Context, principalID uuid.UUID) ([]*KeypairCredential, error) {
	creds, err := s.client.Credential.Query().
		Where(
			credential.PrincipalIDEQ(principalID),
			credential.TypeEQ(credential.TypeKeypair),
		).
		Order(ent.Desc(credential.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list keypairs: %w", err)
	}

	result := make([]*KeypairCredential, len(creds))
	for i, c := range creds {
		result[i] = &KeypairCredential{
			Credential:   entCredentialToModel(c),
			KeyID:        derefStr(c.KeyID),
			KeyAlgorithm: c.KeyAlgorithm,
			PublicKeyPEM: c.PublicKey,
		}
	}
	return result, nil
}

// derefStr dereferences a string pointer, returning empty string if nil.
func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// GetByID retrieves a credential by ID.
func (s *DefaultService) GetByID(ctx context.Context, id uuid.UUID) (*Credential, error) {
	cred, err := s.client.Credential.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("credential not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}
	return entCredentialToModel(cred), nil
}

// Revoke revokes a credential.
func (s *DefaultService) Revoke(ctx context.Context, id uuid.UUID, reason string) error {
	now := time.Now()
	_, err := s.client.Credential.UpdateOneID(id).
		SetRevoked(true).
		SetRevokedAt(now).
		SetRevokedReason(reason).
		SetActive(false).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to revoke credential: %w", err)
	}
	return nil
}

// UpdateLastUsed updates the last used timestamp and IP.
func (s *DefaultService) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	now := time.Now()
	update := s.client.Credential.UpdateOneID(id).
		SetLastUsedAt(now)
	if ip != "" {
		update.SetLastUsedIP(ip)
	}
	_, err := update.Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update last used: %w", err)
	}
	return nil
}

// Helper functions

func entCredentialToModel(c *ent.Credential) *Credential {
	return &Credential{
		ID:            c.ID,
		PrincipalID:   c.PrincipalID,
		Type:          Type(c.Type.String()),
		Identifier:    c.Identifier,
		Name:          c.Name,
		Scopes:        c.Scopes,
		Active:        c.Active,
		ExpiresAt:     c.ExpiresAt,
		Revoked:       c.Revoked,
		RevokedAt:     c.RevokedAt,
		RevokedReason: c.RevokedReason,
		LastUsedAt:    c.LastUsedAt,
		LastUsedIP:    c.LastUsedIP,
		Metadata:      c.Metadata,
		CreatedAt:     c.CreatedAt,
		UpdatedAt:     c.UpdatedAt,
	}
}
