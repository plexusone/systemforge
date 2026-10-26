// Package signup provides user signup and personal organization creation.
//
// The service applies no sign-up policy of SystemAuth's social login, such
// as social_login.signup_minimum_age or invite-only sign-up: an application
// that offers self-service sign-up through it enforces its own policy
// before calling it.
package signup

import (
	"github.com/google/uuid"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/principal"
)

// SignupInput contains input for signing up a new user.
type SignupInput struct {
	// Email is the user's email address (required).
	Email string
	// DisplayName is the user's display name (required).
	DisplayName string
	// GivenName is the user's first name (optional).
	GivenName string
	// FamilyName is the user's last name (optional).
	FamilyName string
	// AvatarURL is the user's avatar URL (optional, often from OAuth provider).
	AvatarURL *string
	// Locale is the user's preferred locale (optional).
	Locale string
	// Timezone is the user's preferred timezone (optional).
	Timezone string
	// PersonalOrgSlug is the URL-safe slug for the personal org (required).
	// Usually derived from email or username.
	PersonalOrgSlug string
	// PersonalOrgName is the display name for the personal org (optional).
	// Defaults to the user's DisplayName if not provided.
	PersonalOrgName string
	// Metadata contains optional metadata for the user.
	Metadata map[string]any
	// EmailVerified asserts that the caller verified Email belongs to the
	// person signing up, for example an identity provider's verified
	// flag. A new account records the email as verified when it is set.
	// SignupOrGetExisting returns an existing account for an email only
	// when it is set and the existing account's own email is verified.
	EmailVerified bool
}

// SignupResult contains the result of a signup operation.
type SignupResult struct {
	// Principal is the created human principal.
	Principal *principal.Principal
	// PersonalOrganization is the created personal organization.
	PersonalOrganization *organization.Organization
	// Membership is the owner membership in the personal organization.
	Membership *organization.Membership
}

// AcceptInviteOnSignupInput contains input for signing up while accepting an invite.
type AcceptInviteOnSignupInput struct {
	// SignupInput contains the user's signup details.
	SignupInput
	// InviteToken is the invitation token to accept.
	InviteToken string
}

// AcceptInviteOnSignupResult contains the result of signing up with an invite.
type AcceptInviteOnSignupResult struct {
	// SignupResult contains the user and personal org.
	SignupResult
	// InvitedOrganizationID is the organization from the invite.
	InvitedOrganizationID uuid.UUID
	// InvitedRole is the role granted by the invite.
	InvitedRole string
}
