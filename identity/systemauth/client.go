package systemauth

import (
	"time"

	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// ClientType defines whether a client is public or confidential.
type ClientType string

const (
	// ClientTypePublic is for clients that cannot keep secrets (SPAs, mobile apps).
	ClientTypePublic ClientType = "public"

	// ClientTypeConfidential is for clients that can keep secrets (server apps).
	ClientTypeConfidential ClientType = "confidential"
)

// Client represents an OAuth 2.0 client.
type Client struct {
	// ID is the client identifier.
	ID string `json:"id"`

	// Secret is the client secret (never serialized).
	Secret string `json:"-"`

	// SecretHash is the bcrypt hash of the secret.
	SecretHash string `json:"secret_hash,omitempty"`

	// Type is "public" or "confidential".
	Type ClientType `json:"type"`

	// Name is a human-readable name.
	Name string `json:"name"`

	// Description is an optional description.
	Description string `json:"description,omitempty"`

	// RedirectURIs are allowed redirect URIs.
	RedirectURIs []string `json:"redirect_uris"`

	// GrantTypes are allowed grant types.
	GrantTypes []string `json:"grant_types"`

	// ResponseTypes are allowed response types.
	ResponseTypes []string `json:"response_types"`

	// Scopes are allowed scopes.
	Scopes []string `json:"scopes"`

	// Audience restricts the token audience.
	Audience []string `json:"audience,omitempty"`

	// AccessTokenLifetime overrides the default for this client.
	AccessTokenLifetime *time.Duration `json:"access_token_lifetime,omitempty"`

	// RefreshTokenLifetime overrides the default for this client.
	RefreshTokenLifetime *time.Duration `json:"refresh_token_lifetime,omitempty"`

	// Metadata holds arbitrary client metadata.
	Metadata map[string]any `json:"metadata,omitempty"`

	// CreatedAt is when the client was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the client was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// Ensure Client implements fosite.Client.
var _ fosite.Client = (*Client)(nil)

// GetID returns the client ID.
func (c *Client) GetID() string {
	return c.ID
}

// GetHashedSecret returns the hashed client secret.
func (c *Client) GetHashedSecret() []byte {
	return []byte(c.SecretHash)
}

// GetRedirectURIs returns the allowed redirect URIs.
func (c *Client) GetRedirectURIs() []string {
	return c.RedirectURIs
}

// GetGrantTypes returns the allowed grant types.
func (c *Client) GetGrantTypes() fosite.Arguments {
	return c.GrantTypes
}

// GetResponseTypes returns the allowed response types.
func (c *Client) GetResponseTypes() fosite.Arguments {
	if len(c.ResponseTypes) == 0 {
		// Default response type for authorization code flow
		return fosite.Arguments{"code"}
	}
	return c.ResponseTypes
}

// GetScopes returns the allowed scopes.
func (c *Client) GetScopes() fosite.Arguments {
	return c.Scopes
}

// IsPublic returns true if the client is public (no secret).
func (c *Client) IsPublic() bool {
	return c.Type == ClientTypePublic
}

// GetAudience returns the allowed audiences.
func (c *Client) GetAudience() fosite.Arguments {
	return c.Audience
}

// NewClientFromConfig creates a Client from a ClientConfig.
func NewClientFromConfig(cfg ClientConfig) (*Client, error) {
	clientType := ClientTypeConfidential
	if cfg.Type == "public" {
		clientType = ClientTypePublic
	}

	client := &Client{
		ID:            cfg.ID,
		Type:          clientType,
		Name:          cfg.Name,
		Description:   cfg.Description,
		RedirectURIs:  cfg.RedirectURIs,
		GrantTypes:    cfg.GrantTypes,
		ResponseTypes: cfg.ResponseTypes,
		Scopes:        cfg.Scopes,
		Audience:      cfg.Audience,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Convert Duration pointers to time.Duration pointers
	if cfg.AccessTokenLifetime != nil {
		d := cfg.AccessTokenLifetime.Duration()
		client.AccessTokenLifetime = &d
	}
	if cfg.RefreshTokenLifetime != nil {
		d := cfg.RefreshTokenLifetime.Duration()
		client.RefreshTokenLifetime = &d
	}

	// Hash the secret if provided
	if cfg.Secret != "" {
		hash, err := hashSecret(cfg.Secret)
		if err != nil {
			return nil, err
		}
		client.SecretHash = hash
	}

	// Apply defaults
	if len(client.GrantTypes) == 0 {
		if client.IsPublic() {
			client.GrantTypes = []string{"authorization_code", "refresh_token"}
		} else {
			client.GrantTypes = []string{"authorization_code", "refresh_token", "client_credentials"}
		}
	}

	if len(client.ResponseTypes) == 0 {
		client.ResponseTypes = []string{"code"}
	}

	return client, nil
}

// hashSecret hashes a client secret using bcrypt.
func hashSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// ValidateSecret checks if the provided secret matches the stored hash.
func (c *Client) ValidateSecret(secret string) bool {
	if c.IsPublic() {
		return true // Public clients don't have secrets
	}

	err := bcrypt.CompareHashAndPassword([]byte(c.SecretHash), []byte(secret))
	return err == nil
}
