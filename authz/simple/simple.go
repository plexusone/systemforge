// Package simple is the former import path of the role-based authorization
// provider.
//
// Deprecated: use github.com/plexusone/systemforge/authz/rbac. The provider
// is unchanged; only the path moved, so that the authorization modes are
// named for what they evaluate (rbac, rebac). This package forwards to the
// new one and will be removed in the next major release. Only what existed
// under this path is forwarded; resource grants and later additions are in
// authz/rbac.
package simple

import "github.com/plexusone/systemforge/authz/rbac"

// Deprecated: use rbac.Provider.
type Provider = rbac.Provider

// Deprecated: use rbac.Option.
type Option = rbac.Option

var (
	// Deprecated: use rbac.New.
	New = rbac.New
	// Deprecated: use rbac.WithManagerRoleGetter.
	WithManagerRoleGetter = rbac.WithManagerRoleGetter
	// Deprecated: use rbac.WithOwnerFullAccess.
	WithOwnerFullAccess = rbac.WithOwnerFullAccess
	// Deprecated: use rbac.WithPermissions.
	WithPermissions = rbac.WithPermissions
	// Deprecated: use rbac.WithPlatformAdminBypass.
	WithPlatformAdminBypass = rbac.WithPlatformAdminBypass
	// Deprecated: use rbac.WithPlatformAdminChecker.
	WithPlatformAdminChecker = rbac.WithPlatformAdminChecker
	// Deprecated: use rbac.WithRoleGetter.
	WithRoleGetter = rbac.WithRoleGetter
	// Deprecated: use rbac.WithRoleHierarchy.
	WithRoleHierarchy = rbac.WithRoleHierarchy
)
