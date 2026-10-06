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
}

// MembershipSource supplies a principal's organization memberships.
//
// SystemAuth is meant to be the source of truth for memberships, roles and
// entitlements: a source that reads them from Claims lets relying parties
// avoid keeping divergent copies. Until SystemAuth emits them, the default
// source reads an app-local table through MembershipLister.
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

// defaultMembershipSource returns explicit when set, otherwise the
// principal store's own table when it has one, otherwise NoMemberships.
func defaultMembershipSource(explicit MembershipSource, store PrincipalStore) MembershipSource {
	if explicit != nil {
		return explicit
	}
	if l, ok := store.(MembershipLister); ok {
		return LocalMemberships(l)
	}
	return NoMemberships
}
