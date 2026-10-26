package scimtoken

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/plexusone/systemforge/identity/scim"
)

// SubjectPrefix starts the SCIM auth subject of a request authenticated
// with a stored token; the token ID follows.
const SubjectPrefix = "scim-token:"

// CredentialOptions configure Service.CredentialFunc.
type CredentialOptions struct {
	// Scopes are the SCIM scopes granted to a tenant token. Default:
	// scim.ScopeFull.
	Scopes []string

	// Platform authenticates platform operator credentials. It is
	// consulted only for bearer tokens that are not in this package's
	// token format, and its credential must have scim.Scope.Platform set;
	// any other credential is refused. When nil, which is the default,
	// only tenant tokens are accepted.
	Platform func(r *http.Request) (scim.Credential, error)
}

// CredentialFunc returns a credential function for
// scim.API.CredentialMiddleware. A bearer token in this package's format is
// authenticated with Authenticate and bound to its organization as a
// tenant (scim.WithTenant). Other bearer tokens go to opts.Platform when it
// is set, and are refused otherwise.
func (s *Service) CredentialFunc(opts CredentialOptions) func(r *http.Request) (scim.Credential, error) {
	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{scim.ScopeFull}
	}
	return func(r *http.Request) (scim.Credential, error) {
		token, ok := bearerToken(r)
		if !ok {
			return scim.Credential{}, scim.ErrUnauthorized("missing bearer token")
		}
		if !strings.HasPrefix(token, Prefix) {
			if opts.Platform == nil {
				return scim.Credential{}, scim.ErrUnauthorized("invalid SCIM credential")
			}
			cred, err := opts.Platform(r)
			if err != nil {
				return scim.Credential{}, err
			}
			if !cred.Scope.Platform || !cred.Scope.Valid() {
				return scim.Credential{}, scim.ErrUnauthorized("invalid SCIM credential")
			}
			return cred, nil
		}
		t, err := s.Authenticate(withRequestInfo(r.Context(), r), token)
		if errors.Is(err, ErrInvalidToken) {
			return scim.Credential{}, scim.ErrUnauthorized("invalid SCIM credential")
		}
		if err != nil {
			return scim.Credential{}, err
		}
		return scim.Credential{
			Subject: SubjectPrefix + t.ID.String(),
			Scopes:  append([]string(nil), scopes...),
			Scope:   scim.Scope{OrganizationID: t.OrganizationID},
		}, nil
	}
}

// bearerToken returns the request's bearer token.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const scheme = "bearer "
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return "", false
	}
	t := strings.TrimSpace(h[len(scheme):])
	return t, t != ""
}

type requestInfoKey struct{}

type requestInfo struct {
	clientIP  string
	userAgent string
}

// withRequestInfo carries the client's address and user agent to the
// audit events Authenticate records.
func withRequestInfo(ctx context.Context, r *http.Request) context.Context {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return context.WithValue(ctx, requestInfoKey{}, requestInfo{clientIP: ip, userAgent: r.UserAgent()})
}
