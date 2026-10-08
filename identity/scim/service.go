package scim

import (
	"context"
)

// Service defines the SCIM service interface for managing users and groups.
type Service interface {
	// User operations.

	// GetUser retrieves a user by ID.
	GetUser(ctx context.Context, id string) (*User, error)

	// ListUsers lists users with optional filtering and pagination.
	ListUsers(ctx context.Context, opts ListOptions) (*ListResponse, error)

	// CreateUser creates a new user.
	CreateUser(ctx context.Context, user *User) (*User, error)

	// UpdateUser replaces a user (PUT semantics).
	UpdateUser(ctx context.Context, id string, user *User, etag string) (*User, error)

	// PatchUser applies partial modifications to a user.
	PatchUser(ctx context.Context, id string, patch *PatchRequest, etag string) (*User, error)

	// DeleteUser removes a user.
	DeleteUser(ctx context.Context, id string) error

	// Group operations.

	// GetGroup retrieves a group by ID.
	GetGroup(ctx context.Context, id string) (*Group, error)

	// ListGroups lists groups with optional filtering and pagination.
	ListGroups(ctx context.Context, opts ListOptions) (*ListResponse, error)

	// CreateGroup creates a new group.
	CreateGroup(ctx context.Context, group *Group) (*Group, error)

	// UpdateGroup replaces a group (PUT semantics).
	UpdateGroup(ctx context.Context, id string, group *Group, etag string) (*Group, error)

	// PatchGroup applies partial modifications to a group.
	PatchGroup(ctx context.Context, id string, patch *PatchRequest, etag string) (*Group, error)

	// DeleteGroup removes a group.
	DeleteGroup(ctx context.Context, id string) error

	// Bulk operations.

	// ProcessBulk processes a bulk request.
	ProcessBulk(ctx context.Context, req *BulkRequest) (*BulkResponse, error)

	// Me operations (optional).

	// GetMe retrieves the current user based on context.
	GetMe(ctx context.Context) (*User, error)

	// PatchMe applies partial modifications to the current user.
	PatchMe(ctx context.Context, patch *PatchRequest, etag string) (*User, error)
}

// Store defines the persistence layer interface for SCIM resources.
// Implementations map SCIM operations to the underlying data store.
type Store interface {
	// User operations.

	// GetUserByID retrieves a user by SCIM ID.
	GetUserByID(ctx context.Context, id string) (*User, error)

	// GetUserByUserName retrieves a user by userName (typically email).
	GetUserByUserName(ctx context.Context, userName string) (*User, error)

	// GetUserByExternalID retrieves a user by externalId.
	GetUserByExternalID(ctx context.Context, externalID string) (*User, error)

	// ListUsers lists users with filtering and pagination.
	// Returns resources, total count, and error.
	ListUsers(ctx context.Context, opts ListOptions) ([]*User, int, error)

	// CreateUser creates a new user.
	CreateUser(ctx context.Context, user *User) (*User, error)

	// UpdateUser updates an existing user.
	UpdateUser(ctx context.Context, id string, user *User) (*User, error)

	// DeleteUser deletes a user.
	DeleteUser(ctx context.Context, id string) error

	// Group operations.

	// GetGroupByID retrieves a group by SCIM ID.
	GetGroupByID(ctx context.Context, id string) (*Group, error)

	// GetGroupByDisplayName retrieves a group by displayName.
	GetGroupByDisplayName(ctx context.Context, displayName string) (*Group, error)

	// GetGroupByExternalID retrieves a group by externalId.
	GetGroupByExternalID(ctx context.Context, externalID string) (*Group, error)

	// ListGroups lists groups with filtering and pagination.
	// Returns resources, total count, and error.
	ListGroups(ctx context.Context, opts ListOptions) ([]*Group, int, error)

	// CreateGroup creates a new group.
	CreateGroup(ctx context.Context, group *Group) (*Group, error)

	// UpdateGroup updates an existing group.
	UpdateGroup(ctx context.Context, id string, group *Group) (*Group, error)

	// DeleteGroup deletes a group.
	DeleteGroup(ctx context.Context, id string) error

	// Membership operations.

	// GetGroupsForUser returns all groups a user belongs to.
	GetGroupsForUser(ctx context.Context, userID string) ([]GroupRef, error)

	// GetMembersForGroup returns all members of a group.
	GetMembersForGroup(ctx context.Context, groupID string) ([]MemberRef, error)

	// AddMemberToGroup adds a user to a group.
	AddMemberToGroup(ctx context.Context, groupID, userID string) error

	// RemoveMemberFromGroup removes a user from a group.
	RemoveMemberFromGroup(ctx context.Context, groupID, userID string) error
}

// AuthorizationHook provides authorization checks for SCIM operations.
type AuthorizationHook interface {
	// CanRead checks if the authenticated user can read the resource.
	CanRead(ctx context.Context, resourceType, resourceID string) error

	// CanCreate checks if the authenticated user can create resources of this type.
	CanCreate(ctx context.Context, resourceType string) error

	// CanUpdate checks if the authenticated user can update the resource.
	CanUpdate(ctx context.Context, resourceType, resourceID string) error

	// CanDelete checks if the authenticated user can delete the resource.
	CanDelete(ctx context.Context, resourceType, resourceID string) error
}

// DenyAllAuthorizationHook refuses every operation. It is the provider's
// default, so a SCIM API mounted without an authorization hook exposes
// nothing.
type DenyAllAuthorizationHook struct{}

// CanRead always refuses.
func (DenyAllAuthorizationHook) CanRead(context.Context, string, string) error { return errDenyAll }

// CanCreate always refuses.
func (DenyAllAuthorizationHook) CanCreate(context.Context, string) error { return errDenyAll }

// CanUpdate always refuses.
func (DenyAllAuthorizationHook) CanUpdate(context.Context, string, string) error { return errDenyAll }

// CanDelete always refuses.
func (DenyAllAuthorizationHook) CanDelete(context.Context, string, string) error { return errDenyAll }

var errDenyAll = ErrForbidden("no authorization hook is configured; see WithAuthorizationHook")

// AllowAllAuthorizationHook allows every operation. Use it only when the
// API is protected another way, such as authentication middleware that
// admits only the identity provider; it is for tests and development
// otherwise.
type AllowAllAuthorizationHook = DefaultAuthorizationHook

// DefaultAuthorizationHook is a no-op authorization hook that allows all
// operations.
//
// Deprecated: despite the name it is not the provider's default any more
// (that is DenyAllAuthorizationHook); use AllowAllAuthorizationHook to
// allow everything explicitly.
type DefaultAuthorizationHook struct{}

// CanRead always allows read operations.
func (DefaultAuthorizationHook) CanRead(ctx context.Context, resourceType, resourceID string) error {
	return nil
}

// CanCreate always allows create operations.
func (DefaultAuthorizationHook) CanCreate(ctx context.Context, resourceType string) error {
	return nil
}

// CanUpdate always allows update operations.
func (DefaultAuthorizationHook) CanUpdate(ctx context.Context, resourceType, resourceID string) error {
	return nil
}

// CanDelete always allows delete operations.
func (DefaultAuthorizationHook) CanDelete(ctx context.Context, resourceType, resourceID string) error {
	return nil
}
