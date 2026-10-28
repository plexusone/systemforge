package appauth

import (
	"encoding/json"
	"net/http"
)

// ResourceMetadataPath is where protected resource metadata (RFC 9728) is
// served, on the application's own origin.
const ResourceMetadataPath = "/.well-known/oauth-protected-resource"

// ResourceMetadata is the protected resource metadata document (RFC 9728
// section 2). It tells a client given only the application's URL where to
// obtain access tokens for it, and whether they must be DPoP-bound.
type ResourceMetadata struct {
	// Resource is the application's resource identifier, its public URL.
	Resource string `json:"resource"`
	// AuthorizationServers are the issuers whose tokens are accepted.
	AuthorizationServers []string `json:"authorization_servers"`
	// BearerMethodsSupported is how tokens are presented.
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	// DPoPSigningAlgValuesSupported are the proof algorithms accepted.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported"`
	// DPoPBoundAccessTokensRequired is true unless unbound tokens are
	// accepted.
	DPoPBoundAccessTokensRequired bool `json:"dpop_bound_access_tokens_required"`
	// ResourceName is Options.ResourceName, for display.
	ResourceName string `json:"resource_name,omitempty"`
}

// ResourceMetadata returns the application's protected resource metadata.
func (a *Authenticator) ResourceMetadata() ResourceMetadata {
	return ResourceMetadata{
		Resource:                      a.resource,
		AuthorizationServers:          []string{a.cfg.Issuer},
		BearerMethodsSupported:        []string{"header"},
		DPoPSigningAlgValuesSupported: []string{"ES256", "ES384", "ES512"},
		DPoPBoundAccessTokensRequired: !a.unbound,
		ResourceName:                  a.name,
	}
}

// ResourceMetadataHandler serves ResourceMetadata as JSON; mount it at
// "GET " + ResourceMetadataPath. The document changes only with the
// configuration, so clients may cache it for an hour.
func (a *Authenticator) ResourceMetadataHandler() http.Handler {
	body, err := json.Marshal(a.ResourceMetadata())
	if err != nil {
		panic("appauth: encoding the resource metadata: " + err.Error()) // strings and bools only
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		if _, err := w.Write(body); err != nil {
			a.logger.Error("appauth: writing the resource metadata", "error", err)
		}
	})
}
