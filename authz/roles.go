package authz

// RoleHierarchy defines a hierarchy of roles where higher values indicate more access.
// Roles with higher hierarchy values can access resources requiring lower levels.
type RoleHierarchy map[string]int

// DefaultRoleHierarchy provides the organization role hierarchy of the
// platform: owner, admin, member and collaborator (plus guest for
// applications that model one).
var DefaultRoleHierarchy = RoleHierarchy{
	"owner":        100,
	"admin":        80,
	"member":       40,
	"collaborator": 20,
	"guest":        10,
}

// CanAccess checks if a user role can access resources requiring the target role.
// Higher hierarchy values can access lower ones.
func (h RoleHierarchy) CanAccess(userRole, requiredRole string) bool {
	userLevel, ok := h[userRole]
	if !ok {
		return false
	}
	requiredLevel, ok := h[requiredRole]
	if !ok {
		return false
	}
	return userLevel >= requiredLevel
}

// Level returns the hierarchy level for a role, or 0 if not found.
func (h RoleHierarchy) Level(role string) int {
	return h[role]
}

// IsHigherOrEqual checks if role1 is higher than or equal to role2.
func (h RoleHierarchy) IsHigherOrEqual(role1, role2 string) bool {
	return h[role1] >= h[role2]
}

// RolePermissions maps roles to their granted permissions.
type RolePermissions map[string][]string

// DefaultRolePermissions provides a common permission mapping.
var DefaultRolePermissions = RolePermissions{
	"owner": {
		"org.delete", "org.manage", "org.settings",
		"member.invite", "member.remove", "member.role.change", "member.list",
		"resource.create", "resource.read", "resource.update", "resource.delete",
	},
	"admin": {
		"org.settings",
		"member.invite", "member.remove", "member.role.change", "member.list",
		"resource.create", "resource.read", "resource.update", "resource.delete",
	},
	"member": {
		"member.list",
		"resource.create", "resource.read", "resource.update",
	},
	// A collaborator holds no organization-wide permission; access to
	// individual resources comes from resource grants (ADR-008).
	"collaborator": {},
}

// HasPermission checks if a role has a specific permission.
func (rp RolePermissions) HasPermission(role, permission string) bool {
	perms, ok := rp[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == permission {
			return true
		}
	}
	return false
}

// HasAnyPermission checks if a role has any of the specified permissions.
func (rp RolePermissions) HasAnyPermission(role string, permissions []string) bool {
	for _, perm := range permissions {
		if rp.HasPermission(role, perm) {
			return true
		}
	}
	return false
}

// HasAllPermissions checks if a role has all of the specified permissions.
func (rp RolePermissions) HasAllPermissions(role string, permissions []string) bool {
	for _, perm := range permissions {
		if !rp.HasPermission(role, perm) {
			return false
		}
	}
	return true
}

// GetPermissions returns all permissions for a role.
func (rp RolePermissions) GetPermissions(role string) []string {
	return rp[role]
}
