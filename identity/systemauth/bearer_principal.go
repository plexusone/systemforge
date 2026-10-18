package systemauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// Bearer authentication errors, returned by BearerPrincipal.
var (
	// ErrBearerMissing means the request carried no bearer token.
	ErrBearerMissing = errors.New("systemauth: no bearer token")
	// ErrBearerInvalid means the token is not an active access token of
	// this server, or does not name a principal.
	ErrBearerInvalid = errors.New("systemauth: invalid bearer token")
	// ErrBearerScope means the token is valid but lacks the required scope.
	ErrBearerScope = errors.New("systemauth: insufficient scope")
)

// BearerGrant is what an access token presented to an API grants: the
// principal it names, the OAuth client it was issued to, and its scopes.
type BearerGrant struct {
	// PrincipalID is the principal the token was issued for.
	PrincipalID uuid.UUID
	// ClientID is the OAuth client the token was issued to.
	ClientID string
	// Scopes are the scopes granted to the token.
	Scopes []string
	// TokenID identifies the token's grant, shared by the tokens of one
	// authorization.
	TokenID string
	// ExpiresAt is when the access token expires; zero when unknown.
	ExpiresAt time.Time
}

// BearerPrincipal authenticates an API request: it returns the principal of
// the request's bearer access token when the token is active, was issued to
// a principal, and was granted scope.
func (s *Server) BearerPrincipal(r *http.Request, scope string) (uuid.UUID, error) {
	g, err := s.BearerAccess(r, scope)
	if err != nil {
		return uuid.Nil, err
	}
	return g.PrincipalID, nil
}

// BearerAccess authenticates an API request as BearerPrincipal does, and
// also returns the client the token was issued to and its scopes, for APIs
// whose checks depend on the calling application.
func (s *Server) BearerAccess(r *http.Request, scope string) (*BearerGrant, error) {
	token := bearerToken(r)
	if token == "" {
		return nil, ErrBearerMissing
	}
	ar, err := s.introspect(r.Context(), token, fosite.AccessToken, s.Session(""))
	if err != nil {
		return nil, ErrBearerInvalid
	}
	id, ok := principalSubject(sessionSubject(ar.GetSession()))
	if !ok {
		return nil, ErrBearerInvalid
	}
	if !ar.GetGrantedScopes().Has(scope) {
		return nil, ErrBearerScope
	}
	g := &BearerGrant{
		PrincipalID: id,
		Scopes:      append([]string(nil), ar.GetGrantedScopes()...),
		TokenID:     ar.GetID(),
		ExpiresAt:   ar.GetSession().GetExpiresAt(fosite.AccessToken),
	}
	if c := ar.GetClient(); c != nil {
		g.ClientID = c.GetID()
	}
	return g, nil
}

// BearerAuthenticator adapts BearerAccess to requestprincipal, for APIs
// served on this server's router behind requestprincipal.Middleware. A
// request with no bearer token carries no credentials of its kind; an
// invalid token is refused with 401 and one without scope with 403, each
// with its RFC 6750 challenge. The principal's Claims["client_id"] is the
// client the token was issued to.
func (s *Server) BearerAuthenticator(scope string) requestprincipal.Authenticator {
	return bearerAuthenticator{s: s, scope: scope}
}

type bearerAuthenticator struct {
	s     *Server
	scope string
}

func (a bearerAuthenticator) Authenticate(r *http.Request) (*requestprincipal.RequestPrincipal, error) {
	g, err := a.s.BearerAccess(r, a.scope)
	if errors.Is(err, ErrBearerMissing) {
		return nil, requestprincipal.ErrNoCredentials
	}
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, ErrBearerScope) {
			status = http.StatusForbidden
		}
		scope := a.scope
		return nil, &requestprincipal.Error{
			Status:  status,
			Respond: func(w http.ResponseWriter) { WriteBearerError(w, err, scope) },
			Err:     err,
		}
	}
	// Type is left unset: an access token names a principal of any type,
	// and the API decides what each type may do.
	return &requestprincipal.RequestPrincipal{
		PrincipalID: g.PrincipalID.String(),
		Subject:     g.PrincipalID.String(),
		Session:     g.TokenID,
		Protocol:    requestprincipal.ProtocolOIDC,
		Scopes:      g.Scopes,
		Proof: requestprincipal.Proof{
			Method:    "access_token",
			Issuer:    a.s.config.Issuer,
			TokenID:   g.TokenID,
			ExpiresAt: g.ExpiresAt,
		},
		Claims: map[string]any{"client_id": g.ClientID},
	}, nil
}

// Challenge implements requestprincipal.Challenger.
func (a bearerAuthenticator) Challenge(h http.Header) {
	h.Set("WWW-Authenticate", `Bearer realm="systemauth"`)
}

// WriteBearerError writes the RFC 6750 response for an error from
// BearerPrincipal: 401 with a challenge for a missing or invalid token, 403
// naming the scope for an insufficient one.
func WriteBearerError(w http.ResponseWriter, err error, scope string) {
	switch {
	case errors.Is(err, ErrBearerScope):
		writeBearerError(w, http.StatusForbidden, "insufficient_scope", "The access token was not granted the required scope.", scope)
	case errors.Is(err, ErrBearerInvalid):
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "The access token is invalid, expired or revoked.", "")
	default:
		writeBearerError(w, http.StatusUnauthorized, "", "", "")
	}
}
