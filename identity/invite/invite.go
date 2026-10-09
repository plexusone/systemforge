// Package invite provides organization invitation management.
package invite

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Status represents the status of an invite.
type Status string

const (
	StatusPending  Status = "pending"
	StatusAccepted Status = "accepted"
	StatusDeclined Status = "declined"
	StatusExpired  Status = "expired"
	StatusRevoked  Status = "revoked"
)

// Invite represents an invitation to join an organization.
type Invite struct {
	ID                 uuid.UUID
	OrganizationID     uuid.UUID
	InviterPrincipalID uuid.UUID
	Email              string
	Role               string
	// AppRoles are the application roles granted when the invite is
	// accepted: application identifier to role. Empty means none.
	AppRoles              map[string]string
	Status                Status
	Message               *string
	ExpiresAt             time.Time
	AcceptedAt            *time.Time
	AcceptedByPrincipalID *uuid.UUID
	ResendCount           int
	LastSentAt            time.Time
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// IsExpired returns true if the invite has expired.
func (i *Invite) IsExpired() bool {
	return time.Now().After(i.ExpiresAt)
}

// IsPending returns true if the invite is still pending.
func (i *Invite) IsPending() bool {
	return i.Status == StatusPending && !i.IsExpired()
}

// CanAccept returns true if the invite can be accepted.
func (i *Invite) CanAccept() bool {
	return i.Status == StatusPending && !i.IsExpired()
}

// CreateInviteInput contains input for creating an invite.
type CreateInviteInput struct {
	OrganizationID     uuid.UUID
	InviterPrincipalID uuid.UUID
	Email              string
	Role               string
	// AppRoles are the application roles to grant on acceptance:
	// application identifier to role. None is preselected; an inviter
	// chooses each. With an approle service configured (WithAppRoles),
	// an admin or member invitation to an organization entitled to any
	// application must name at least one (ErrAppRoleRequired).
	AppRoles  map[string]string
	Message   *string
	ExpiresIn time.Duration // How long until expiry (default: 7 days)
}

// AcceptInviteInput contains input for accepting an invite.
type AcceptInviteInput struct {
	Token       string
	PrincipalID uuid.UUID // The principal accepting the invite
}

// ListInvitesInput contains filters for listing invites.
type ListInvitesInput struct {
	OrganizationID *uuid.UUID
	Email          *string
	Status         *Status
	Limit          int
	Offset         int
}

// InviteResult contains the result of invite operations.
type InviteResult struct {
	Invite *Invite
	// InviteURL is the full URL to accept the invite
	InviteURL string
}

// ErrAppRoleRequired means an admin or member invitation chose no
// application role although the organization is entitled to applications
// (ADR-007: nobody gets into an application by being a member alone, and
// an invitation must open at least one).
var ErrAppRoleRequired = errors.New("invite: choose an application role for at least one entitled application")

// Default invite expiration time.
const DefaultInviteExpiry = 7 * 24 * time.Hour // 7 days
