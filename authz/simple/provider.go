// Package simple provides a simple role-based authorization provider.
//
// This provider uses role hierarchy and permission mappings to make authorization
// decisions. It has no external dependencies and is suitable for applications
// with straightforward RBAC requirements.
package simple

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
)

// Provider implements the Authorizer interface using role hierarchy and permissions.
type Provider struct {
	hierarchy   authz.RoleHierarchy
	permissions authz.RolePermissions

	// Callbacks for looking up data
	getRoleFn       func(ctx context.Context, principalID, orgID uuid.UUID) (string, error)
	isPlatformAdmin func(ctx context.Context, principalID uuid.UUID) (bool, error)
	managerRoles    authz.ManagerRoleGetter

	// Options
	allowOwnerFullAccess bool
	platformAdminBypass  bool
}

// Option configures an Provider.
type Option func(*Provider)

// WithRoleHierarchy sets a custom role hierarchy.
func WithRoleHierarchy(h authz.RoleHierarchy) Option {
	return func(a *Provider) {
		a.hierarchy = h
	}
}

// WithPermissions sets a custom permission mapping.
func WithPermissions(p authz.RolePermissions) Option {
	return func(a *Provider) {
		a.permissions = p
	}
}

// WithRoleGetter sets the function to retrieve a principal's role in an organization.
func WithRoleGetter(fn func(ctx context.Context, principalID, orgID uuid.UUID) (string, error)) Option {
	return func(a *Provider) {
		a.getRoleFn = fn
	}
}

// WithPlatformAdminChecker sets the function to check platform admin status.
func WithPlatformAdminChecker(fn func(ctx context.Context, principalID uuid.UUID) (bool, error)) Option {
	return func(a *Provider) {
		a.isPlatformAdmin = fn
	}
}

// WithManagerRoleGetter sets the function that returns the manager roles
// one principal holds over another. With it, permissions on
// authz.ResourceTypePrincipal resources follow authz.ManagerRolePermissions,
// matching the principal relations of the SpiceDB base schema.
func WithManagerRoleGetter(fn authz.ManagerRoleGetter) Option {
	return func(a *Provider) {
		a.managerRoles = fn
	}
}

// WithOwnerFullAccess enables full access for resource owners.
func WithOwnerFullAccess(enabled bool) Option {
	return func(a *Provider) {
		a.allowOwnerFullAccess = enabled
	}
}

// WithPlatformAdminBypass enables platform admin bypass for all checks.
func WithPlatformAdminBypass(enabled bool) Option {
	return func(a *Provider) {
		a.platformAdminBypass = enabled
	}
}

// New creates a new simple Provider with the given options.
func New(opts ...Option) *Provider {
	a := &Provider{
		hierarchy:            authz.DefaultRoleHierarchy,
		permissions:          authz.DefaultRolePermissions,
		allowOwnerFullAccess: true,
		platformAdminBypass:  true,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Can checks if a principal can perform an action on a resource.
func (a *Provider) Can(ctx context.Context, principal authz.Principal, action authz.Action, resource authz.Resource) (bool, error) {
	// Check platform admin bypass
	if a.platformAdminBypass && a.isPlatformAdmin != nil {
		isAdmin, err := a.isPlatformAdmin(ctx, principal.ID)
		if err != nil {
			return false, fmt.Errorf("checking platform admin: %w", err)
		}
		if isAdmin {
			return true, nil
		}
	}

	// Check owner access
	if a.allowOwnerFullAccess && resource.IsOwner(principal.ID) {
		return true, nil
	}

	if resource.Type == authz.ResourceTypePrincipal && resource.ID != nil {
		role, err := a.managerRoleFor(ctx, principal.ID, *resource.ID, action)
		return role != "", err
	}
	if isBaseOrgCheck(resource, action) {
		role, err := a.orgRole(ctx, principal.ID, resource)
		return authz.OrgRoleAllows(role, action), err
	}

	// Get organization ID from resource
	if resource.OrgID == nil {
		// No org context - check type-level permission without org role
		return a.checkPermissionWithoutOrg(principal, action, resource)
	}

	// Get principal's role in the organization
	if a.getRoleFn == nil {
		return false, nil
	}

	role, err := a.getRoleFn(ctx, principal.ID, *resource.OrgID)
	if err != nil {
		return false, fmt.Errorf("getting role: %w", err)
	}
	if role == "" {
		return false, nil // Not a member
	}

	// Build permission string: resource.type.action
	permission := buildPermission(resource.Type, action)

	return a.permissions.HasPermission(role, permission), nil
}

// CanAll checks if a principal can perform all specified actions on a resource.
func (a *Provider) CanAll(ctx context.Context, principal authz.Principal, actions []authz.Action, resource authz.Resource) (bool, error) {
	for _, action := range actions {
		allowed, err := a.Can(ctx, principal, action, resource)
		if err != nil {
			return false, err
		}
		if !allowed {
			return false, nil
		}
	}
	return true, nil
}

// CanAny checks if a principal can perform any of the specified actions on a resource.
func (a *Provider) CanAny(ctx context.Context, principal authz.Principal, actions []authz.Action, resource authz.Resource) (bool, error) {
	for _, action := range actions {
		allowed, err := a.Can(ctx, principal, action, resource)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

// Filter returns only the resources the principal can access with the given action.
func (a *Provider) Filter(ctx context.Context, principal authz.Principal, action authz.Action, resources []authz.Resource) ([]authz.Resource, error) {
	var allowed []authz.Resource
	for _, resource := range resources {
		can, err := a.Can(ctx, principal, action, resource)
		if err != nil {
			return nil, err
		}
		if can {
			allowed = append(allowed, resource)
		}
	}
	return allowed, nil
}

// CanForOrg checks permission scoped to a specific organization.
func (a *Provider) CanForOrg(ctx context.Context, principal authz.Principal, orgID uuid.UUID, action authz.Action, resource authz.Resource) (bool, error) {
	// Create a copy of resource with org ID set
	resourceWithOrg := resource.WithOrg(orgID)
	return a.Can(ctx, principal, action, resourceWithOrg)
}

// GetRole returns the principal's role in an organization.
func (a *Provider) GetRole(ctx context.Context, principal authz.Principal, orgID uuid.UUID) (string, error) {
	if a.getRoleFn == nil {
		return "", nil
	}
	return a.getRoleFn(ctx, principal.ID, orgID)
}

// IsMember checks if a principal is a member of an organization.
func (a *Provider) IsMember(ctx context.Context, principal authz.Principal, orgID uuid.UUID) (bool, error) {
	role, err := a.GetRole(ctx, principal, orgID)
	if err != nil {
		return false, err
	}
	return role != "", nil
}

// IsPlatformAdmin checks if a principal has platform-wide admin access.
func (a *Provider) IsPlatformAdmin(ctx context.Context, principal authz.Principal) (bool, error) {
	if a.isPlatformAdmin == nil {
		return false, nil
	}
	return a.isPlatformAdmin(ctx, principal.ID)
}

// Decide returns a detailed authorization decision.
func (a *Provider) Decide(ctx context.Context, principal authz.Principal, action authz.Action, resource authz.Resource) (authz.Decision, error) {
	// Check platform admin bypass
	if a.platformAdminBypass && a.isPlatformAdmin != nil {
		isAdmin, err := a.isPlatformAdmin(ctx, principal.ID)
		if err != nil {
			return authz.Decision{Allowed: false, Reason: "error checking admin status"}, err
		}
		if isAdmin {
			return authz.Decision{Allowed: true, Reason: "platform admin bypass"}, nil
		}
	}

	// Check owner access
	if a.allowOwnerFullAccess && resource.IsOwner(principal.ID) {
		return authz.Decision{Allowed: true, Reason: "resource owner"}, nil
	}

	if resource.Type == authz.ResourceTypePrincipal && resource.ID != nil {
		role, err := a.managerRoleFor(ctx, principal.ID, *resource.ID, action)
		if err != nil {
			return authz.Decision{Allowed: false, Reason: "error getting manager roles"}, err
		}
		if role == "" {
			return authz.Decision{Allowed: false, Reason: fmt.Sprintf("no manager role grants %s", action)}, nil
		}
		return authz.Decision{
			Allowed:  true,
			Reason:   fmt.Sprintf("manager role %s grants %s", role, action),
			PolicyID: fmt.Sprintf("manager:%s:permission:%s", role, action),
		}, nil
	}

	if isBaseOrgCheck(resource, action) {
		role, err := a.orgRole(ctx, principal.ID, resource)
		if err != nil {
			return authz.Decision{Allowed: false, Reason: "error getting role"}, err
		}
		if !authz.OrgRoleAllows(role, action) {
			return authz.Decision{Allowed: false, Reason: fmt.Sprintf("organization role %q lacks %s", role, action)}, nil
		}
		return authz.Decision{
			Allowed:  true,
			Reason:   fmt.Sprintf("organization role %s grants %s", role, action),
			PolicyID: fmt.Sprintf("org:%s:permission:%s", role, action),
		}, nil
	}

	// Get organization ID from resource
	if resource.OrgID == nil {
		allowed, err := a.checkPermissionWithoutOrg(principal, action, resource)
		reason := "no organization context"
		if allowed {
			reason = "type-level permission granted"
		}
		return authz.Decision{Allowed: allowed, Reason: reason}, err
	}

	// Get principal's role in the organization
	if a.getRoleFn == nil {
		return authz.Decision{Allowed: false, Reason: "no role getter configured"}, nil
	}

	role, err := a.getRoleFn(ctx, principal.ID, *resource.OrgID)
	if err != nil {
		return authz.Decision{Allowed: false, Reason: "error getting role"}, err
	}
	if role == "" {
		return authz.Decision{Allowed: false, Reason: "not a member of organization"}, nil
	}

	// Build permission string: resource.type.action
	permission := buildPermission(resource.Type, action)

	if a.permissions.HasPermission(role, permission) {
		return authz.Decision{
			Allowed:  true,
			Reason:   fmt.Sprintf("role %s has permission %s", role, permission),
			PolicyID: fmt.Sprintf("role:%s:permission:%s", role, permission),
		}, nil
	}

	return authz.Decision{
		Allowed: false,
		Reason:  fmt.Sprintf("role %s lacks permission %s", role, permission),
	}, nil
}

// isBaseOrgCheck reports a check of a base organization permission (such
// as manage or view) on an organization, which follows
// authz.OrgRolePermissions so that it matches the SpiceDB base schema.
func isBaseOrgCheck(resource authz.Resource, action authz.Action) bool {
	return resource.Type == authz.ResourceTypeOrganization && authz.IsOrgPermission(action)
}

// orgRole returns the principal's role in the organization resource,
// which is identified by its ID (or, failing that, its OrgID).
func (a *Provider) orgRole(ctx context.Context, principalID uuid.UUID, resource authz.Resource) (string, error) {
	orgID := resource.ID
	if orgID == nil {
		orgID = resource.OrgID
	}
	if orgID == nil || a.getRoleFn == nil {
		return "", nil
	}
	role, err := a.getRoleFn(ctx, principalID, *orgID)
	if err != nil {
		return "", fmt.Errorf("getting role: %w", err)
	}
	return role, nil
}

// managerRoleFor returns a manager role managerID holds over managedID
// that grants action, or "" when none does.
func (a *Provider) managerRoleFor(ctx context.Context, managerID, managedID uuid.UUID, action authz.Action) (string, error) {
	if a.managerRoles == nil {
		return "", nil
	}
	roles, err := a.managerRoles(ctx, managerID, managedID)
	if err != nil {
		return "", fmt.Errorf("getting manager roles: %w", err)
	}
	for _, role := range roles {
		if authz.ManagerRoleAllows(role, action) {
			return role, nil
		}
	}
	return "", nil
}

// checkPermissionWithoutOrg handles authorization when no org context is available.
//
//nolint:unparam // action reserved for future fine-grained checks
func (a *Provider) checkPermissionWithoutOrg(principal authz.Principal, action authz.Action, resource authz.Resource) (bool, error) {
	// Without org context, only allow if principal owns the resource
	if a.allowOwnerFullAccess && resource.IsOwner(principal.ID) {
		return true, nil
	}
	return false, nil
}

// buildPermission creates a permission string from resource type and action.
func buildPermission(resourceType authz.ResourceType, action authz.Action) string {
	return strings.ToLower(string(resourceType)) + "." + strings.ToLower(string(action))
}

// Verify Provider implements the required interfaces.
var (
	_ authz.Authorizer         = (*Provider)(nil)
	_ authz.OrgAuthorizer      = (*Provider)(nil)
	_ authz.PlatformAuthorizer = (*Provider)(nil)
	_ authz.DecisionAuthorizer = (*Provider)(nil)
)
