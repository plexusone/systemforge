// Package invite provides organization invitation management.
package invite

import (
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
	ID                    uuid.UUID
	OrganizationID        uuid.UUID
	InviterPrincipalID    uuid.UUID
	Email                 string
	Role                  string
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
	Message            *string
	ExpiresIn          time.Duration // How long until expiry (default: 7 days)
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

// Default invite expiration time.
const DefaultInviteExpiry = 7 * 24 * time.Hour // 7 days
