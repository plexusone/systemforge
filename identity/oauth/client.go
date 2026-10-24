package oauth

import (
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent"
)

// Client implements fosite.Client backed by Ent OAuthApp.
type Client struct {
	app     *ent.OAuthApp
	storage *Storage
	// secretHashes are the client's active secret hashes, newest first.
	secretHashes []string
}

var (
	_ fosite.Client                   = (*Client)(nil)
	_ fosite.ClientWithSecretRotation = (*Client)(nil)
)

// GetID returns the client ID.
func (c *Client) GetID() string {
	return c.app.ClientID
}

// GetHashedSecret returns the hash of the client's newest active secret,
// or nil for a client without one.
func (c *Client) GetHashedSecret() []byte {
	if len(c.secretHashes) == 0 {
		return nil
	}
	return []byte(c.secretHashes[0])
}

// GetRotatedHashes returns the hashes of the client's other active
// secrets, accepted during a secret rotation.
func (c *Client) GetRotatedHashes() [][]byte {
	if len(c.secretHashes) < 2 {
		return nil
	}
	out := make([][]byte, 0, len(c.secretHashes)-1)
	for _, h := range c.secretHashes[1:] {
		out = append(out, []byte(h))
	}
	return out
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
