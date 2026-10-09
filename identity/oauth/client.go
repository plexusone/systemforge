package oauth

import (
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent"
)

// Client implements fosite.Client backed by Ent OAuthApp.
type Client struct {
	app     *ent.OAuthApp
	storage *Storage
}

var _ fosite.Client = (*Client)(nil)

// GetID returns the client ID.
func (c *Client) GetID() string {
	return c.app.ClientID
}

// GetHashedSecret returns nothing - we use custom validation.
func (c *Client) GetHashedSecret() []byte {
	// We use Argon2id and validate separately
	return nil
}

// GetRedirectURIs returns the registered redirect URIs.
func (c *Client) GetRedirectURIs() []string {
	return c.app.RedirectUris
}

// GetGrantTypes returns the allowed grant types.
func (c *Client) GetGrantTypes() fosite.Arguments {
	return c.app.AllowedGrants
}

// GetResponseTypes returns the allowed response types.
func (c *Client) GetResponseTypes() fosite.Arguments {
	return c.app.AllowedResponseTypes
}

// GetScopes returns the allowed scopes.
func (c *Client) GetScopes() fosite.Arguments {
	return c.app.AllowedScopes
}

// IsPublic returns true if this is a public client (SPA, native app).
func (c *Client) IsPublic() bool {
	return c.app.Public
}

// GetAudience returns the audience for this client.
func (c *Client) GetAudience() fosite.Arguments {
	// Default to the client ID as audience
	return fosite.Arguments{c.app.ClientID}
}
