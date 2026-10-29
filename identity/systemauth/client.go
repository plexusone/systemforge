package systemauth

import (
	"context"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"

	"github.com/plexusone/systemforge/identity/accesschange"
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

	// SecretHash is the hash of the secret (bcrypt, or Argon2id in PHC
	// string format; see ClientSecretHasher).
	SecretHash string `json:"secret_hash,omitempty"`

	// RotatedSecretHashes are the hashes of other secrets that are
	// still active, accepted during a secret rotation.
	RotatedSecretHashes []string `json:"-"`

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

	// ManagedPrincipalsEnabled allows this client to create and sign in
	// managed principals. It takes effect only when the deployment also
	// enables managed principals (see Server.ManagedPrincipalsAllowed).
	ManagedPrincipalsEnabled bool `json:"managed_principals_enabled,omitempty"`

	// LoginTokenTTL overrides the deployment's default lifetime of reusable
	// login tokens for this client's managed principals; nil uses it.
	LoginTokenTTL *time.Duration `json:"login_token_ttl,omitempty"`

	// BackchannelLogoutURI is the client's endpoint for OIDC Back-Channel
	// Logout tokens, which also carry access-change events (ADR-010). It
	// must be an https URL (http is allowed for loopback hosts); empty means
	// the client receives none.
	BackchannelLogoutURI string `json:"backchannel_logout_uri,omitempty"`

	// AllowBearerTokens is a legacy exception that lets the client get
	// unbound bearer tokens by calling the token endpoint without a DPoP
	// proof. Without it every token request must carry a valid proof and
	// every token is bound to the proof's key (DPoPBoundAccessTokens).
	AllowBearerTokens bool `json:"allow_bearer_tokens,omitempty"`

	// Party says who owns the client: PartyFirst, PartySecond or
	// PartyThird. Only first-party clients skip the consent screen. Empty
	// means PartyThird; NewClientFromConfig sets PartyFirst for a client
	// declared in the configuration file without one.
	Party ClientParty `json:"party,omitempty"`

	// LogoURL is an optional https URL of the client's logo, shown on the
	// login page when the client started the sign-in.
	LogoURL string `json:"logo_url,omitempty"`

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

// GetRotatedHashes returns the hashes of the other active secrets
// (fosite.ClientWithSecretRotation), accepted alongside SecretHash.
func (c *Client) GetRotatedHashes() [][]byte {
	out := make([][]byte, 0, len(c.RotatedSecretHashes))
	for _, h := range c.RotatedSecretHashes {
		out = append(out, []byte(h))
	}
	return out
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

// DPoPBoundAccessTokens is the client's RFC 9449 dpop_bound_access_tokens
// metadata: true, the default, means the client always uses DPoP and a
// token request without a proof is refused. It is false only for a client
// registered with the AllowBearerTokens exception.
func (c *Client) DPoPBoundAccessTokens() bool {
	return !c.AllowBearerTokens
}

// NewClientFromConfig creates a Client from a ClientConfig. A client
// without a party is first-party: the configuration file declares the
// operator's own applications.
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
		// Managed principals are opt-in per client.
		ManagedPrincipalsEnabled: cfg.ManagedPrincipals,
		BackchannelLogoutURI:     cfg.BackchannelLogoutURI,
		AllowBearerTokens:        cfg.AllowBearerTokens,
		Party:                    ClientParty(cfg.Party),
		LogoURL:                  cfg.LogoURL,
		UpdatedAt:                time.Now(),
	}
	// Clients in the configuration file are the operator's own
	// applications unless they say otherwise.
	if client.Party == "" {
		client.Party = PartyFirst
	}
	if err := ValidateBackchannelLogoutURI(client.BackchannelLogoutURI); err != nil {
		return nil, fmt.Errorf("client %q: %w", cfg.ID, err)
	}
	if err := validateClientMetadata(client); err != nil {
		return nil, err
	}

	// Convert Duration pointers to time.Duration pointers
	if cfg.AccessTokenLifetime != nil {
		d := accesschange.ClampAccessTokenLifetime(cfg.AccessTokenLifetime.Duration())
		client.AccessTokenLifetime = &d
	}
	if cfg.RefreshTokenLifetime != nil {
		d := cfg.RefreshTokenLifetime.Duration()
		client.RefreshTokenLifetime = &d
	}
	if cfg.LoginTokenTTL != nil {
		d := cfg.LoginTokenTTL.Duration()
		client.LoginTokenTTL = &d
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

// ValidateSecret checks if the provided secret matches the stored hash or,
// during a rotation, one of the other active secrets.
func (c *Client) ValidateSecret(secret string) bool {
	if c.IsPublic() {
		return true // Public clients don't have secrets
	}
	for _, h := range append([]string{c.SecretHash}, c.RotatedSecretHashes...) {
		if h != "" && (ClientSecretHasher{}).Compare(context.Background(), []byte(h), []byte(secret)) == nil {
			return true
		}
	}
	return false
}
