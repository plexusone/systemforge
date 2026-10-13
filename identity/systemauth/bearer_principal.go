package systemauth

import (
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/ory/fosite"
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

// BearerPrincipal authenticates an API request: it returns the principal of
// the request's bearer access token when the token is active, was issued to
// a principal, and was granted scope.
func (s *Server) BearerPrincipal(r *http.Request, scope string) (uuid.UUID, error) {
	token := bearerToken(r)
	if token == "" {
		return uuid.Nil, ErrBearerMissing
	}
	ar, err := s.introspect(r.Context(), token, fosite.AccessToken, s.Session(""))
	if err != nil {
		return uuid.Nil, ErrBearerInvalid
	}
	id, ok := principalSubject(sessionSubject(ar.GetSession()))
	if !ok {
		return uuid.Nil, ErrBearerInvalid
	}
	if !ar.GetGrantedScopes().Has(scope) {
		return uuid.Nil, ErrBearerScope
	}
	return id, nil
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
