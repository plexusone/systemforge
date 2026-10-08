package authz

import (
	"context"

	"github.com/google/uuid"
)

// ResourceTypePrincipal is the resource type for permissions one principal
// holds over another, such as a manager over a managed principal.
const ResourceTypePrincipal ResourceType = "principal"

// Built-in manager roles (ADR-005). They are relations on principal in the
// base SpiceDB schema.
const (
	// ManagerRoleGuardian has full authority over a managed principal.
	ManagerRoleGuardian = "guardian"
	// ManagerRoleEducator has operational authority: credentials and
	// profile reads, without account or manager administration.
	ManagerRoleEducator = "educator"
)

// Platform permissions a manager holds over a principal.
const (
	// PermManageAccount covers consent, deletion, and billing.
	PermManageAccount Action = "manage_account"
	// PermManageCredentials covers issuing and revoking sign-in
	// credentials and sessions.
	PermManageCredentials Action = "manage_credentials" //nolint:gosec // G101: a permission name, not a credential
	// PermViewProfile covers reading the principal's profile.
	PermViewProfile Action = "view_profile"
	// PermManageManagers covers adding and removing other managers.
	PermManageManagers Action = "manage_managers"
)

// ManagerRolePermissions maps each built-in manager role to its platform
// permissions, mirroring the principal definition in BaseSpiceDBSchema.
var ManagerRolePermissions = map[string][]Action{
	ManagerRoleGuardian: {PermManageAccount, PermManageCredentials, PermViewProfile, PermManageManagers},
	ManagerRoleEducator: {PermManageCredentials, PermViewProfile},
}

// ManagerRoleAllows reports whether a manager role grants a permission.
func ManagerRoleAllows(role string, action Action) bool {
	for _, a := range ManagerRolePermissions[role] {
		if a == action {
			return true
		}
	}
	return false
}

// ManagerRoleGetter returns the active manager roles managerID holds over
// managedID, or none.
type ManagerRoleGetter func(ctx context.Context, managerID, managedID uuid.UUID) ([]string, error)

// NewPrincipalResource returns the resource for permissions over a
// principal.
func NewPrincipalResource(id uuid.UUID) Resource {
	return NewResourceWithID(ResourceTypePrincipal, id)
}
