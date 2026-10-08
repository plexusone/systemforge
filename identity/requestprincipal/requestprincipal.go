// Package requestprincipal is the protocol-neutral view of who made an HTTP
// request. A resource server (a product API) protects its routes with one
// middleware that tries several Authenticators in order — a human's BFF
// cookie or bearer token, an API key, an AI agent's AAuth-signed request —
// and finds a RequestPrincipal in the request context, whichever protocol
// authenticated it.
//
// The package has no protocol dependencies. Adapters live with their
// protocols: relyingparty.NewRequestAuthenticator wraps SystemAuth bearer
// tokens, API keys and BFF sessions, and the aauthrs subpackage verifies
// AAuth (agent auth) requests.
package requestprincipal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

// Type is the kind of party a request principal is.
type Type string

const (
	// TypeHuman is an interactive person.
	TypeHuman Type = "human"
	// TypeAgent is an AI agent, possibly acting for a person.
	TypeAgent Type = "agent"
	// TypeService is a backend service or system account.
	TypeService Type = "service"
	// TypeApplication is an OAuth client acting as itself.
	TypeApplication Type = "application"
)

// Protocol values for RequestPrincipal.Protocol.
const (
	// ProtocolSession is a browser (BFF) cookie session.
	ProtocolSession = "session"
	// ProtocolOIDC is an OAuth 2.0 / OpenID Connect bearer access token.
	ProtocolOIDC = "oidc"
	// ProtocolAPIKey is an API key.
	ProtocolAPIKey = "apikey"
	// ProtocolAAuth is an AAuth HTTP message signature with an agent,
	// person or auth token.
	ProtocolAAuth = "aauth"
)

// RequestPrincipal is the authenticated principal of one request.
type RequestPrincipal struct {
	// PrincipalID is the stable identifier the application keys
	// authorization and records on: the app-local principal ID for
	// SystemAuth credentials, or an issuer-qualified subject for
	// credentials issued elsewhere (see the adapter's documentation).
	PrincipalID string
	// Type is the kind of party that made the request.
	Type Type
	// Subject is the credential's subject as its issuer states it. It is
	// unique within Proof.Issuer only.
	Subject string
	// Organization is the organization (tenant) the credential is scoped
	// to, when it is scoped to one.
	Organization string
	// Actor identifies the party that made the request when it is not
	// the subject: for an agent acting for a person, the agent.
	Actor string
	// Delegator identifies the party the actor acts for, when there is
	// one: for an agent acting for a person, the person.
	Delegator string
	// Mission identifies the task the credential was issued for, when
	// the protocol has one (AAuth: the mission's s256 digest).
	Mission string
	// Session identifies the authenticated session or grant: a BFF
	// session or an issued token's ID.
	Session string
	// Protocol is how the request authenticated (Protocol*).
	Protocol string
	// Proof is the verified evidence behind the principal.
	Proof Proof
	// Scopes are the scopes or grants the credential carries. Empty for
	// a session, which carries the principal's full access.
	Scopes []string
	// Claims are additional verified attributes, by name.
	Claims map[string]any
	// Native is the adapter's own, protocol-specific result (for example
	// *relyingparty.AuthenticatedPrincipal), for callers that need more
	// than the neutral view.
	Native any
}

// Proof is the verified evidence an authenticator accepted.
type Proof struct {
	// Method names the credential form (e.g. "access_token", "api_key",
	// "session", "aa-auth+jwt").
	Method string
	// Issuer is the party that issued the credential.
	Issuer string
	// Audience is the audience the credential was verified for.
	Audience string
	// TokenID is the credential's identifier (a JWT jti or an API key ID).
	TokenID string
	// KeyThumbprint is the RFC 7638 thumbprint of the key the request was
	// signed with, for proof-of-possession credentials.
	KeyThumbprint string
	// IssuedAt and ExpiresAt bound the credential, when it states them.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// Params are further protocol-specific evidence (e.g. the signature's
	// covered components), by name.
	Params map[string]string
}

// HasScope reports whether the principal's credential carries scope.
func (p *RequestPrincipal) HasScope(scope string) bool {
	return slices.Contains(p.Scopes, scope)
}

// IsAgent reports whether the request was made by an AI agent.
func (p *RequestPrincipal) IsAgent() bool { return p.Type == TypeAgent }

type contextKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p *RequestPrincipal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

// FromContext returns the request principal in ctx, if any.
func FromContext(ctx context.Context) (*RequestPrincipal, bool) {
	p, ok := ctx.Value(contextKey{}).(*RequestPrincipal)
	return p, ok && p != nil
}

// ErrNoPrincipal is returned by PrincipalUUID when the request carries no
// principal that is a SystemForge principal.
var ErrNoPrincipal = errors.New("requestprincipal: no SystemForge principal")

// PrincipalUUID returns the SystemForge principal ID of the request's
// principal. It returns ErrNoPrincipal when the request is
// unauthenticated or its principal ID is not a SystemForge principal ID,
// such as an issuer-qualified subject of a credential issued elsewhere.
func PrincipalUUID(ctx context.Context) (uuid.UUID, error) {
	p, ok := FromContext(ctx)
	if !ok {
		return uuid.Nil, ErrNoPrincipal
	}
	id, err := uuid.Parse(p.PrincipalID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %q", ErrNoPrincipal, p.PrincipalID)
	}
	return id, nil
}
