package relyingparty

import "errors"

var (
	// ErrInvalidToken is returned when an ID token or access token fails
	// verification (signature, issuer, audience, nonce or expiry).
	ErrInvalidToken = errors.New("relyingparty: invalid token")

	// ErrPrincipalNotFound is returned by PrincipalStore lookups that find
	// nothing.
	ErrPrincipalNotFound = errors.New("relyingparty: principal not found")

	// ErrPrincipalInactive is returned when the resolved principal is
	// disabled.
	ErrPrincipalInactive = errors.New("relyingparty: principal is inactive")

	// ErrEmailNotVerified is returned when an unlinked identity has no
	// verified email: such an identity can neither link to nor create a
	// principal.
	ErrEmailNotVerified = errors.New("relyingparty: identity email is not verified")

	// ErrEmailConflict is returned when the identity's email belongs to a
	// local principal that cannot be linked automatically (its own email
	// is unverified, or it is already linked to another SystemAuth
	// principal).
	ErrEmailConflict = errors.New("relyingparty: email belongs to a principal that cannot be linked")

	// ErrSubjectLinked is returned by PrincipalStore writes when the
	// SystemAuth subject is already linked to a principal (a lost race).
	ErrSubjectLinked = errors.New("relyingparty: subject already linked")

	// ErrSessionNotFound is returned by SessionStore lookups for unknown or
	// expired sessions.
	ErrSessionNotFound = errors.New("relyingparty: session not found")

	// ErrInvalidState is returned for unknown, used or expired login state.
	ErrInvalidState = errors.New("relyingparty: invalid or expired login state")
)
