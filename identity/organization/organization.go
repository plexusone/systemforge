// Package organization provides organization management services.
package organization

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// OrgType represents the type of organization.
type OrgType string

const (
	OrgTypePersonal   OrgType = "personal"   // Personal namespace for a user
	OrgTypeTeam       OrgType = "team"       // Shared team organization
	OrgTypeEnterprise OrgType = "enterprise" // Enterprise organization
)

// Organization represents an organization in the system.
type Organization struct {
	ID               uuid.UUID
	Name             string
	Slug             string
	OrgType          OrgType
	OwnerPrincipalID *uuid.UUID // For personal orgs
	LogoURL          *string
	Description      *string
	WebsiteURL       *string
	Settings         map[string]any
	Active           bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// IsPersonal returns true if this is a personal organization.
func (o *Organization) IsPersonal() bool {
	return o.OrgType == OrgTypePersonal
}

// CreateOrganizationInput contains input for creating an organization.
type CreateOrganizationInput struct {
	Name             string
	Slug             string
	OrgType          OrgType
	OwnerPrincipalID *uuid.UUID // Required for personal orgs
	LogoURL          *string
	Description      *string
	WebsiteURL       *string
	Settings         map[string]any
}

// CreatePersonalOrgInput contains input for creating a personal organization.
type CreatePersonalOrgInput struct {
	OwnerPrincipalID uuid.UUID
	Name             string  // Display name (usually user's name)
	Slug             string  // URL-safe username
	LogoURL          *string // Optional avatar
}

// UpdateOrganizationInput contains input for updating an organization.
type UpdateOrganizationInput struct {
	Name        *string
	LogoURL     *string
	Description *string
	WebsiteURL  *string
	Settings    map[string]any
}

// ListOrganizationsInput contains filters for listing organizations.
type ListOrganizationsInput struct {
	OrgType *OrgType
	Active  *bool
	// MemberPrincipalID limits the list to organizations the principal is
	// an active member of.
	MemberPrincipalID *uuid.UUID
	Limit             int
	Offset            int
}

// Membership represents a principal's membership in an organization.
type Membership struct {
	ID             uuid.UUID
	PrincipalID    uuid.UUID
	OrganizationID uuid.UUID
	Role           string
	Permissions    []string
	Active         bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// MembershipRole constants for common roles.
const (
	RoleOwner  = "owner"
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// AddMemberInput contains input for adding a member to an organization.
type AddMemberInput struct {
	OrganizationID uuid.UUID
	PrincipalID    uuid.UUID
	Role           string
	Permissions    []string
}

// UpdateMemberInput contains input for updating a membership.
type UpdateMemberInput struct {
	Role        *string
	Permissions []string
	Active      *bool
}

// TransferOwnershipInput contains input for transferring organization ownership.
type TransferOwnershipInput struct {
	OrganizationID uuid.UUID
	FromPrincipal  uuid.UUID // Current owner
	ToPrincipal    uuid.UUID // New owner
	NewRoleForOld  string    // Role for the previous owner (default: "admin")
}

// ErrMembershipNotFound is returned when a principal has no membership,
// active or not, in an organization.
var ErrMembershipNotFound = errors.New("membership not found")
