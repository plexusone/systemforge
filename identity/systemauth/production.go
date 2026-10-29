package systemauth

import (
	"slices"

	"github.com/ory/fosite"
)

// grantTypeClientCredentials is the OAuth 2.0 client credentials grant.
const grantTypeClientCredentials = "client_credentials"

// ProductionPolicy refuses, at the token endpoint, what a production
// deployment must not serve. The checks run at request time, so they also
// cover clients registered after startup. The packaged service
// (systemauthsvc) sets both outside development mode unless
// production.allow waives them.
type ProductionPolicy struct {
	// RefuseClientSecretClientCredentials refuses the client_credentials
	// grant to a client authenticated with a shared client secret, with
	// unauthorized_client. The client's other grants are unaffected:
	// confidential clients keep using their secret for authorization_code
	// and refresh_token. Service accounts with the JWT-bearer grant replace
	// it.
	RefuseClientSecretClientCredentials bool

	// RefuseBearerTokenClients refuses every token request from a client
	// registered with AllowBearerTokens, with unauthorized_client, so no
	// token is issued that is not bound to a DPoP key.
	RefuseBearerTokenClients bool
}

// WithProductionPolicy sets the checks the token endpoint applies to
// clients.
func WithProductionPolicy(p ProductionPolicy) Option {
	return func(s *Server) { s.production = p }
}

// checkProductionPolicy applies the production policy to an authenticated
// token request. The error is a standard OAuth error without internal
// detail; the reason is for the server log.
func (s *Server) checkProductionPolicy(ar fosite.AccessRequester) (reason string, err error) {
	c, ok := ar.GetClient().(*Client)
	if !ok {
		return "", nil
	}
	if s.production.RefuseBearerTokenClients && c.AllowBearerTokens {
		return "the client is registered with allow_bearer_tokens", fosite.ErrUnauthorizedClient
	}
	if s.production.RefuseClientSecretClientCredentials && !c.IsPublic() && slices.Contains(ar.GetGrantTypes(), grantTypeClientCredentials) {
		// SystemAuth clients authenticate at the token endpoint with a
		// shared secret (client_secret_basic or client_secret_post).
		return "the client_credentials grant with a shared client secret is refused", fosite.ErrUnauthorizedClient
	}
	return "", nil
}

// clientCredentialsServed reports whether the client_credentials grant is
// served, for discovery.
func (s *Server) clientCredentialsServed() bool {
	return !s.production.RefuseClientSecretClientCredentials
}
