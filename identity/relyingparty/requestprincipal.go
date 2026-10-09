package relyingparty

import (
	"errors"
	"net/http"

	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// bearerChallenge is the WWW-Authenticate challenge for requests without
// credentials.
const bearerChallenge = `Bearer realm="api"` //nolint:gosec // G101: an authentication challenge, not a credential

// RequestAuthenticator adapts BearerConfig to a
// requestprincipal.Authenticator, so SystemAuth access tokens, API keys and
// BFF sessions can share one requestprincipal.Middleware with other
// protocols (such as AAuth for AI agents).
type RequestAuthenticator struct {
	cfg BearerConfig
}

// NewRequestAuthenticator returns an Authenticator accepting what
// BearerMiddleware accepts with cfg. Requests with no Authorization or
// X-API-Key header and no BFF session are left to the next authenticator.
func NewRequestAuthenticator(cfg BearerConfig) *RequestAuthenticator {
	if cfg.Principals == nil {
		panic("relyingparty: BearerConfig.Principals is required")
	}
	cfg.Memberships = defaultMembershipSource(cfg.Memberships)
	return &RequestAuthenticator{cfg: cfg}
}

// Authenticate implements requestprincipal.Authenticator. The result's
// Native is the *AuthenticatedPrincipal, which carries the memberships.
func (a *RequestAuthenticator) Authenticate(r *http.Request) (*requestprincipal.RequestPrincipal, error) {
	p, err := a.cfg.authenticate(r)
	if err != nil {
		if errors.Is(err, errNoCredentials) {
			return nil, requestprincipal.ErrNoCredentials
		}
		var authErr *bearerError
		if !errors.As(err, &authErr) {
			return nil, err
		}
		challenge := bearerChallenge
		if authErr.code != "" {
			challenge += `, error="` + authErr.code + `"`
		}
		return nil, &requestprincipal.Error{
			Status:  http.StatusUnauthorized,
			Header:  http.Header{"Www-Authenticate": {challenge}},
			Code:    "UNAUTHENTICATED",
			Message: authErr.message,
			Err:     err,
		}
	}
	return ToRequestPrincipal(p), nil
}

// Challenge implements requestprincipal.Challenger.
func (a *RequestAuthenticator) Challenge(h http.Header) {
	h.Add("WWW-Authenticate", bearerChallenge)
}

// ToRequestPrincipal converts an AuthenticatedPrincipal to the
// protocol-neutral view. PrincipalID is the app-local principal ID.
func ToRequestPrincipal(p *AuthenticatedPrincipal) *requestprincipal.RequestPrincipal {
	rp := &requestprincipal.RequestPrincipal{
		PrincipalID: p.ID,
		Type:        requestPrincipalType(p.Type),
		Subject:     p.Subject,
		Scopes:      p.Scopes,
		Proof:       requestprincipal.Proof{Method: string(p.Method)},
		Native:      p,
	}
	switch p.Method {
	case AuthMethodSession:
		rp.Protocol = requestprincipal.ProtocolSession
	case AuthMethodAccessToken:
		rp.Protocol = requestprincipal.ProtocolOIDC
	case AuthMethodAPIKey:
		rp.Protocol = requestprincipal.ProtocolAPIKey
		rp.Proof.TokenID = p.APIKeyID
	}
	return rp
}

func requestPrincipalType(t string) requestprincipal.Type {
	switch t {
	case "", "human":
		return requestprincipal.TypeHuman
	case "client":
		return requestprincipal.TypeApplication
	}
	return requestprincipal.Type(t)
}

var (
	_ requestprincipal.Authenticator = (*RequestAuthenticator)(nil)
	_ requestprincipal.Challenger    = (*RequestAuthenticator)(nil)
)
