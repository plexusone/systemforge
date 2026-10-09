package identity

import (
	"context"

	"github.com/google/uuid"
)

// UserInfo represents basic user information returned by services.
type UserInfo struct {
	ID              uuid.UUID
	Email           string
	Name            string
	AvatarURL       *string
	IsPlatformAdmin bool
	Active          bool
}

// OrganizationInfo represents basic organization information.
type OrganizationInfo struct {
	ID       uuid.UUID
	Name     string
	Slug     string
	LogoURL  *string
	Settings map[string]any
	Active   bool
}

// MembershipInfo represents a user's membership in an organization.
type MembershipInfo struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	OrganizationID uuid.UUID
	Role           string
	Permissions    []string
}

// UserService defines operations for user management.
type UserService interface {
	// GetByID retrieves a user by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*UserInfo, error)

	// GetByEmail retrieves a user by email address.
	GetByEmail(ctx context.Context, email string) (*UserInfo, error)

	// Create creates a new user.
	Create(ctx context.Context, input CreateUserInput) (*UserInfo, error)

	// Update updates an existing user.
	Update(ctx context.Context, id uuid.UUID, input UpdateUserInput) (*UserInfo, error)

	// Delete soft-deletes a user by setting active=false.
	Delete(ctx context.Context, id uuid.UUID) error

	// SetPassword sets a user's password hash.
	SetPassword(ctx context.Context, id uuid.UUID, password string) error

	// VerifyPassword verifies a user's password.
	VerifyPassword(ctx context.Context, id uuid.UUID, password string) (bool, error)

	// UpdateLastLogin updates the user's last login timestamp.
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
}

// CreateUserInput contains fields for creating a new user.
type CreateUserInput struct {
	Email           string
	Name            string
	AvatarURL       *string
	Password        *string `json:"-"` // Optional, hashed before storage (never serialized) //nolint:gosec // G117: field holds user-provided value, not a hardcoded secret
	IsPlatformAdmin bool
}

// UpdateUserInput contains fields for updating a user.
type UpdateUserInput struct {
	Email           *string
	Name            *string
	AvatarURL       *string
	IsPlatformAdmin *bool
	Active          *bool
}

// OrganizationService defines operations for organization management.
type OrganizationService interface {
	// GetByID retrieves an organization by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*OrganizationInfo, error)

	// GetBySlug retrieves an organization by slug.
	GetBySlug(ctx context.Context, slug string) (*OrganizationInfo, error)

	// Create creates a new organization.
	Create(ctx context.Context, input CreateOrganizationInput) (*OrganizationInfo, error)

	// Update updates an existing organization.
	Update(ctx context.Context, id uuid.UUID, input UpdateOrganizationInput) (*OrganizationInfo, error)

	// Delete soft-deletes an organization.
	Delete(ctx context.Context, id uuid.UUID) error

	// ListForUser lists all organizations a user is a member of.
	ListForUser(ctx context.Context, userID uuid.UUID) ([]*OrganizationInfo, error)
}

// CreateOrganizationInput contains fields for creating an organization.
type CreateOrganizationInput struct {
	Name     string
	Slug     string
	LogoURL  *string
	Settings map[string]any
}

// UpdateOrganizationInput contains fields for updating an organization.
type UpdateOrganizationInput struct {
	Name     *string
	Slug     *string
	LogoURL  *string
	Settings map[string]any
	Active   *bool
}

// MembershipService defines operations for membership management.
type MembershipService interface {
	// GetByID retrieves a membership by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*MembershipInfo, error)

	// GetByUserAndOrg retrieves a user's membership in a specific organization.
	GetByUserAndOrg(ctx context.Context, userID, orgID uuid.UUID) (*MembershipInfo, error)

	// Create adds a user to an organization with a role.
	Create(ctx context.Context, input CreateMembershipInput) (*MembershipInfo, error)

	// Update updates a membership's role or permissions.
	Update(ctx context.Context, id uuid.UUID, input UpdateMembershipInput) (*MembershipInfo, error)

	// Delete removes a user from an organization.
	Delete(ctx context.Context, id uuid.UUID) error

	// ListForOrg lists all members of an organization.
	ListForOrg(ctx context.Context, orgID uuid.UUID) ([]*MembershipInfo, error)

	// ListForUser lists all memberships for a user.
	ListForUser(ctx context.Context, userID uuid.UUID) ([]*MembershipInfo, error)

	// HasRole checks if a user has a specific role in an organization.
	HasRole(ctx context.Context, userID, orgID uuid.UUID, role string) (bool, error)

	// HasAnyRole checks if a user has any of the specified roles.
	HasAnyRole(ctx context.Context, userID, orgID uuid.UUID, roles []string) (bool, error)
}

// CreateMembershipInput contains fields for creating a membership.
type CreateMembershipInput struct {
	UserID         uuid.UUID
	OrganizationID uuid.UUID
	Role           string
	Permissions    []string
}

// UpdateMembershipInput contains fields for updating a membership.
type UpdateMembershipInput struct {
	Role        *string
	Permissions []string
}

// OAuthAccountInfo represents an OAuth provider connection.
type OAuthAccountInfo struct {
	ID             uuid.UUID
	UserID         uuid.UUID
	Provider       string
	ProviderUserID string
}

// OAuthService defines operations for OAuth account management.
type OAuthService interface {
	// GetByProviderUser retrieves an OAuth account by provider and external user ID.
	GetByProviderUser(ctx context.Context, provider, providerUserID string) (*OAuthAccountInfo, error)

	// Create links an OAuth account to a user.
	Create(ctx context.Context, input CreateOAuthAccountInput) (*OAuthAccountInfo, error)

	// Delete removes an OAuth account link.
	Delete(ctx context.Context, id uuid.UUID) error

	// ListForUser lists all OAuth accounts for a user.
	ListForUser(ctx context.Context, userID uuid.UUID) ([]*OAuthAccountInfo, error)
}

// CreateOAuthAccountInput contains fields for creating an OAuth account.
//
//nolint:gosec // G117: fields hold runtime values from OAuth provider, not hardcoded secrets
type CreateOAuthAccountInput struct {
	UserID         uuid.UUID
	Provider       string
	ProviderUserID string
	AccessToken    *string `json:"-"` // Never serialized
	RefreshToken   *string `json:"-"` // Never serialized
}
