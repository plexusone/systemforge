package relyingparty

import (
	"context"
)

// MembershipQuery identifies whose organization memberships to load.
type MembershipQuery struct {
	// Principal is the resolved app-local principal.
	Principal *Principal

	// Subject is the SystemAuth subject (sf_principal_id), when known.
	Subject string

	// Claims are the verified SystemAuth claims seen for this request: the
	// ID token and UserInfo claims stored with a BFF session, or the claims
	// of a JWT access token. Nil for API keys.
	Claims map[string]any

	// AccessToken returns a valid SystemAuth access token for the request
	// (the presented JWT, or a session's token, refreshed when it is about
	// to expire). It is nil when the request has none, as with an API key.
	// It is lazy so that sources reading claims never trigger a refresh.
	AccessToken func(ctx context.Context) (string, error)
}

// MembershipSource supplies a principal's organization memberships.
//
// SystemAuth is the source of truth for memberships, roles and entitlements
// (ADR-007). The default source, ClaimsMemberships, reads them from the
// verified claims; RemoteMemberships reads them from SystemAuth's
// memberships endpoint; LocalMemberships reads an app-local table and is
// for development and tests only.
type MembershipSource interface {
	Memberships(ctx context.Context, q MembershipQuery) ([]Membership, error)
}

// MembershipSourceFunc adapts a function to MembershipSource.
type MembershipSourceFunc func(ctx context.Context, q MembershipQuery) ([]Membership, error)

// Memberships implements MembershipSource.
func (f MembershipSourceFunc) Memberships(ctx context.Context, q MembershipQuery) ([]Membership, error) {
	return f(ctx, q)
}

// MembershipLister is an app-local membership table. MemoryPrincipalStore
// implements it.
type MembershipLister interface {
	// Memberships lists the principal's organization memberships.
	Memberships(ctx context.Context, principalID string) ([]Membership, error)
}

// LocalMemberships reads memberships from an app-local MembershipLister.
//
// It is for development and tests only. A table the application keeps
// itself diverges from SystemAuth (members removed or roles changed there
// are not seen here), which is what ADR-007 removes. Production
// applications use ClaimsMemberships or RemoteMemberships.
func LocalMemberships(l MembershipLister) MembershipSource {
	return MembershipSourceFunc(func(ctx context.Context, q MembershipQuery) ([]Membership, error) {
		if q.Principal == nil {
			return nil, nil
		}
		return l.Memberships(ctx, q.Principal.ID)
	})
}

// NoMemberships reports no memberships.
var NoMemberships MembershipSource = MembershipSourceFunc(func(context.Context, MembershipQuery) ([]Membership, error) {
	return nil, nil
})

// defaultMembershipSource returns explicit when set, otherwise
// ClaimsMemberships.
func defaultMembershipSource(explicit MembershipSource) MembershipSource {
	if explicit != nil {
		return explicit
	}
	return ClaimsMemberships
}
