// Package providertest provides conformance tests for authz.Provider implementations.
package providertest

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
)

// Verify MockProvider implements the required interfaces.
var (
	_ authz.Authorizer         = (*MockProvider)(nil)
	_ authz.OrgAuthorizer      = (*MockProvider)(nil)
	_ authz.PlatformAuthorizer = (*MockProvider)(nil)
	_ authz.DecisionAuthorizer = (*MockProvider)(nil)
)

// MockProvider is a mock implementation of authz interfaces for testing.
type MockProvider struct {
	name        string
	hierarchy   authz.RoleHierarchy
	permissions authz.RolePermissions

	// Configurable behaviors
	roles         map[string]map[string]string // principalID -> orgID -> role
	platformAdmin map[string]bool              // principalID -> isPlatformAdmin

	// Test hooks for customization
	CanFunc             func(ctx context.Context, principal authz.Principal, action authz.Action, resource authz.Resource) (bool, error)
	IsPlatformAdminFunc func(ctx context.Context, principal authz.Principal) (bool, error)
}

// NewMockProvider creates a new mock provider with default configuration.
func NewMockProvider() *MockProvider {
	return &MockProvider{
		name:          "mock",
		hierarchy:     authz.DefaultRoleHierarchy,
		permissions:   authz.DefaultRolePermissions,
		roles:         make(map[string]map[string]string),
		platformAdmin: make(map[string]bool),
	}
}

// Name returns the provider name.
func (m *MockProvider) Name() string {
	return m.name
}

// SetRole sets a principal's role in an organization.
func (m *MockProvider) SetRole(principalID, orgID uuid.UUID, role string) {
	pid := principalID.String()
	if m.roles[pid] == nil {
		m.roles[pid] = make(map[string]string)
	}
	m.roles[pid][orgID.String()] = role
}

// SetPlatformAdmin sets a principal's platform admin status.
func (m *MockProvider) SetPlatformAdmin(principalID uuid.UUID, isAdmin bool) {
	m.platformAdmin[principalID.String()] = isAdmin
}

// SetHierarchy sets the role hierarchy.
func (m *MockProvider) SetHierarchy(h authz.RoleHierarchy) {
	m.hierarchy = h
}

// SetPermissions sets the role permissions.
func (m *MockProvider) SetPermissions(p authz.RolePermissions) {
	m.permissions = p
}

// Can checks if a principal can perform an action on a resource.
func (m *MockProvider) Can(ctx context.Context, principal authz.Principal, action authz.Action, resource authz.Resource) (bool, error) {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	// Use custom function if provided
	if m.CanFunc != nil {
		return m.CanFunc(ctx, principal, action, resource)
	}

	// Check platform admin bypass
	if m.platformAdmin[principal.ID.String()] {
		return true, nil
	}

	// Check owner access
	if resource.IsOwner(principal.ID) {
		return true, nil
	}

	// Get role and check permission
	if resource.OrgID == nil {
		return false, nil
	}

	role := m.getRole(principal.ID, *resource.OrgID)
	if role == "" {
		return false, nil
	}

	permission := fmt.Sprintf("%s.%s", resource.Type, action)
	return m.permissions.HasPermission(role, permission), nil
}

// CanAll checks if a principal can perform all specified actions on a resource.
// An empty action list is denied rather than vacuously allowed.
func (m *MockProvider) CanAll(ctx context.Context, principal authz.Principal, actions []authz.Action, resource authz.Resource) (bool, error) {
	if len(actions) == 0 {
		return false, nil
	}
	for _, action := range actions {
		allowed, err := m.Can(ctx, principal, action, resource)
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
func (m *MockProvider) CanAny(ctx context.Context, principal authz.Principal, actions []authz.Action, resource authz.Resource) (bool, error) {
	for _, action := range actions {
		allowed, err := m.Can(ctx, principal, action, resource)
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
func (m *MockProvider) Filter(ctx context.Context, principal authz.Principal, action authz.Action, resources []authz.Resource) ([]authz.Resource, error) {
	var allowed []authz.Resource
	for _, resource := range resources {
		can, err := m.Can(ctx, principal, action, resource)
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
func (m *MockProvider) CanForOrg(ctx context.Context, principal authz.Principal, orgID uuid.UUID, action authz.Action, resource authz.Resource) (bool, error) {
	resourceWithOrg := resource.WithOrg(orgID)
	return m.Can(ctx, principal, action, resourceWithOrg)
}

// GetRole returns the principal's role in an organization.
func (m *MockProvider) GetRole(ctx context.Context, principal authz.Principal, orgID uuid.UUID) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	return m.getRole(principal.ID, orgID), nil
}

// IsMember checks if a principal is a member of an organization.
func (m *MockProvider) IsMember(ctx context.Context, principal authz.Principal, orgID uuid.UUID) (bool, error) {
	role, err := m.GetRole(ctx, principal, orgID)
	if err != nil {
		return false, err
	}
	return role != "", nil
}

// IsPlatformAdmin checks if a principal has platform-wide admin access.
func (m *MockProvider) IsPlatformAdmin(ctx context.Context, principal authz.Principal) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	if m.IsPlatformAdminFunc != nil {
		return m.IsPlatformAdminFunc(ctx, principal)
	}

	return m.platformAdmin[principal.ID.String()], nil
}

// Decide returns a detailed authorization decision.
func (m *MockProvider) Decide(ctx context.Context, principal authz.Principal, action authz.Action, resource authz.Resource) (authz.Decision, error) {
	// Check context cancellation
	select {
	case <-ctx.Done():
		return authz.Decision{Allowed: false, Reason: "context cancelled"}, ctx.Err()
	default:
	}

	// Check platform admin bypass
	if m.platformAdmin[principal.ID.String()] {
		return authz.Decision{Allowed: true, Reason: "platform admin bypass"}, nil
	}

	// Check owner access
	if resource.IsOwner(principal.ID) {
		return authz.Decision{Allowed: true, Reason: "resource owner"}, nil
	}

	// Get role and check permission
	if resource.OrgID == nil {
		return authz.Decision{Allowed: false, Reason: "no organization context"}, nil
	}

	role := m.getRole(principal.ID, *resource.OrgID)
	if role == "" {
		return authz.Decision{Allowed: false, Reason: "not a member of organization"}, nil
	}

	permission := fmt.Sprintf("%s.%s", resource.Type, action)
	if m.permissions.HasPermission(role, permission) {
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

// getRole returns the role for a principal in an organization.
func (m *MockProvider) getRole(principalID, orgID uuid.UUID) string {
	pid := principalID.String()
	oid := orgID.String()
	if orgRoles, ok := m.roles[pid]; ok {
		return orgRoles[oid]
	}
	return ""
}
