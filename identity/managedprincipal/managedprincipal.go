// Package managedprincipal manages humans without an email: managed
// principals, such as young learners, whose accounts are created and
// controlled by managers who do have an email (ADR-005).
//
// The package enforces the invariants: a managed principal can be created
// only when the deployment and the requesting client both allow it, always
// has at least one active manager, and every manager is an active human
// with an email who is not itself managed.
package managedprincipal

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/credential"
)

// Built-in manager roles.
const (
	// RoleGuardian has full authority: consent, deletion, billing, sign-in
	// credentials, and adding or removing other managers.
	RoleGuardian = "guardian"
	// RoleEducator has operational authority: sign-in credentials and
	// reading the profile, without deletion, billing, or consent.
	RoleEducator = "educator"
)

var (
	// ErrNotAllowed is returned when the deployment or the requesting
	// client does not allow managed principals.
	ErrNotAllowed = errors.New("managedprincipal: managed principals are not enabled for this client")
	// ErrDisplayNameRequired is returned when creating a managed principal
	// without a display name.
	ErrDisplayNameRequired = errors.New("managedprincipal: display name is required")
	// ErrNoManagers is returned when creating a managed principal without
	// a manager.
	ErrNoManagers = errors.New("managedprincipal: at least one manager is required")
	// ErrInvalidManager is returned when a manager is not an active human
	// with an email, or is itself managed.
	ErrInvalidManager = errors.New("managedprincipal: manager must be an active human with an email")
	// ErrInvalidRole is returned for a manager role that is not registered.
	ErrInvalidRole = errors.New("managedprincipal: unknown manager role")
	// ErrNotManaged is returned when the principal is not a human, or for
	// operations that apply only to managed principals, has an email.
	ErrNotManaged = errors.New("managedprincipal: principal is not a managed human")
	// ErrLastManager is returned when removing the last active manager of
	// a principal that has no email.
	ErrLastManager = errors.New("managedprincipal: cannot remove the last manager of a principal without an email")
	// ErrNotManager is returned when the acting principal is not an
	// active manager of the managed principal.
	ErrNotManager = errors.New("managedprincipal: not an active manager of this principal")
	// ErrForbidden is returned when the acting principal lacks the
	// permission an operation requires.
	ErrForbidden = errors.New("managedprincipal: forbidden")
	// ErrNotFound is returned when a principal or relationship does not exist.
	ErrNotFound = errors.New("managedprincipal: not found")
)

// Gate reports whether a client may create and sign in managed
// principals, and the login token lifetimes that apply to it.
// *systemauth.Server implements it: ManagedPrincipalsAllowed requires both
// the deployment setting and the client's flag, and LoginTokenPolicy
// applies the client's own default lifetime over the deployment's.
type Gate interface {
	ManagedPrincipalsAllowed(ctx context.Context, clientID string) (bool, error)
	LoginTokenPolicy(ctx context.Context, clientID string) (credential.LoginTokenPolicy, error)
}

// ManagerInput names a manager and the role it holds.
type ManagerInput struct {
	PrincipalID uuid.UUID
	Role        string
}

// CreateInput describes a managed principal to create.
type CreateInput struct {
	// ClientID is the OAuth client making the request; it must allow
	// managed principals.
	ClientID string
	// DisplayName is the name shown for the managed principal.
	DisplayName string
	// Managers must contain at least one manager.
	Managers []ManagerInput
	// ActorID is the principal performing the action, for the audit trail.
	ActorID uuid.UUID
}

// Relationship is an active or inactive manager relationship.
type Relationship struct {
	ManagedPrincipalID uuid.UUID
	ManagerPrincipalID uuid.UUID
	Role               string
	Active             bool
}

// IssueLoginTokenInput describes a login token to issue for a managed
// principal.
type IssueLoginTokenInput struct {
	// ManagedID is the managed principal the token signs in.
	ManagedID uuid.UUID
	// ClientID is the OAuth client requesting the token; it must allow
	// managed principals and supplies the default lifetime.
	ClientID string
	// IssuedBy is the issuing manager.
	IssuedBy uuid.UUID
	// ExpiresAt optionally sets the expiry; it is clamped to the ceiling.
	ExpiresAt *time.Time
	// SingleUse makes the token valid for one sign-in.
	SingleUse bool
	// Name optionally labels the token, such as the card or device.
	Name string
}
