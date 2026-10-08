package simple_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/providertest"
	"github.com/plexusone/systemforge/authz/simple"
)

// TestConformance runs the full conformance test suite for the simple provider.
func TestConformance(t *testing.T) {
	principalID := uuid.New()
	orgID := uuid.New()

	// In-memory role storage for testing
	roles := map[string]map[string]string{
		principalID.String(): {
			orgID.String(): "admin",
		},
	}
	platformAdmins := map[string]bool{}
	managers := map[[2]uuid.UUID][]string{} // {manager, managed} -> roles

	provider := simple.New(
		simple.WithRoleHierarchy(authz.DefaultRoleHierarchy),
		simple.WithPermissions(authz.DefaultRolePermissions),
		simple.WithRoleGetter(func(ctx context.Context, pid, oid uuid.UUID) (string, error) {
			if orgRoles, ok := roles[pid.String()]; ok {
				return orgRoles[oid.String()], nil
			}
			return "", nil
		}),
		simple.WithPlatformAdminChecker(func(ctx context.Context, pid uuid.UUID) (bool, error) {
			return platformAdmins[pid.String()], nil
		}),
		simple.WithManagerRoleGetter(func(_ context.Context, manager, managed uuid.UUID) ([]string, error) {
			return managers[[2]uuid.UUID{manager, managed}], nil
		}),
		simple.WithOwnerFullAccess(true),
		simple.WithPlatformAdminBypass(true),
	)

	providertest.RunAll(t, providertest.Config{
		Provider:        provider,
		SkipIntegration: false,
		TestPrincipalID: principalID,
		TestOrgID:       orgID,
		GrantManager: func(_ *testing.T, managed, manager uuid.UUID, role string) {
			k := [2]uuid.UUID{manager, managed}
			managers[k] = append(managers[k], role)
		},
	})
}

// TestInterfaceConformance verifies simple.Provider implements all expected interfaces.
func TestInterfaceConformance(t *testing.T) {
	provider := simple.New()

	// Verify interface implementation via type assertions
	var _ authz.Authorizer = provider
	var _ authz.OrgAuthorizer = provider
	var _ authz.PlatformAuthorizer = provider
	var _ authz.DecisionAuthorizer = provider
}

// TestWithCustomHierarchy tests custom role hierarchy.
func TestWithCustomHierarchy(t *testing.T) {
	principalID := uuid.New()
	orgID := uuid.New()

	customHierarchy := authz.RoleHierarchy{
		"superadmin": 100,
		"admin":      80,
		"user":       40,
	}

	customPermissions := authz.RolePermissions{
		"superadmin": {"resource.create", "resource.read", "resource.update", "resource.delete"},
		"admin":      {"resource.create", "resource.read", "resource.update"},
		"user":       {"resource.read"},
	}

	roles := map[string]map[string]string{
		principalID.String(): {
			orgID.String(): "admin",
		},
	}

	provider := simple.New(
		simple.WithRoleHierarchy(customHierarchy),
		simple.WithPermissions(customPermissions),
		simple.WithRoleGetter(func(ctx context.Context, pid, oid uuid.UUID) (string, error) {
			if orgRoles, ok := roles[pid.String()]; ok {
				return orgRoles[oid.String()], nil
			}
			return "", nil
		}),
	)

	principal := authz.NewUserPrincipal(principalID)
	resource := authz.NewOrgResource(authz.ResourceType("resource"), orgID)

	// Admin should have update access
	allowed, err := provider.Can(context.Background(), principal, authz.ActionUpdate, resource)
	if err != nil {
		t.Fatalf("Can(update) error: %v", err)
	}
	if !allowed {
		t.Error("Admin should have update permission")
	}

	// Admin should NOT have delete access
	allowed, err = provider.Can(context.Background(), principal, authz.ActionDelete, resource)
	if err != nil {
		t.Fatalf("Can(delete) error: %v", err)
	}
	if allowed {
		t.Error("Admin should NOT have delete permission")
	}
}

// TestDecideReturnsDetailedDecision tests the Decide method returns detailed decisions.
func TestDecideReturnsDetailedDecision(t *testing.T) {
	principalID := uuid.New()
	orgID := uuid.New()

	roles := map[string]map[string]string{
		principalID.String(): {
			orgID.String(): "viewer",
		},
	}

	provider := simple.New(
		simple.WithRoleGetter(func(ctx context.Context, pid, oid uuid.UUID) (string, error) {
			if orgRoles, ok := roles[pid.String()]; ok {
				return orgRoles[oid.String()], nil
			}
			return "", nil
		}),
	)

	principal := authz.NewUserPrincipal(principalID)
	resource := authz.NewOrgResource(authz.ResourceType("resource"), orgID)

	// Viewer has read permission
	decision, err := provider.Decide(context.Background(), principal, authz.ActionRead, resource)
	if err != nil {
		t.Fatalf("Decide(read) error: %v", err)
	}
	if !decision.Allowed {
		t.Error("Decide(read).Allowed = false for viewer, want true")
	}
	if decision.Reason == "" {
		t.Error("Decide(read).Reason should not be empty")
	}
	if decision.PolicyID == "" {
		t.Error("Decide(read).PolicyID should not be empty when allowed")
	}

	// Viewer does NOT have delete permission
	decision, err = provider.Decide(context.Background(), principal, authz.ActionDelete, resource)
	if err != nil {
		t.Fatalf("Decide(delete) error: %v", err)
	}
	if decision.Allowed {
		t.Error("Decide(delete).Allowed = true for viewer, want false")
	}
	if decision.Reason == "" {
		t.Error("Decide(delete).Reason should not be empty")
	}
}

// TestOwnerBypass tests owner full access bypass.
func TestOwnerBypass(t *testing.T) {
	ownerID := uuid.New()
	resourceID := uuid.New()

	provider := simple.New(
		simple.WithOwnerFullAccess(true),
	)

	principal := authz.NewUserPrincipal(ownerID)
	resource := authz.NewOwnedResource(authz.ResourceType("document"), resourceID, ownerID)

	// Owner should have delete access even without role
	allowed, err := provider.Can(context.Background(), principal, authz.ActionDelete, resource)
	if err != nil {
		t.Fatalf("Can(delete) error: %v", err)
	}
	if !allowed {
		t.Error("Owner should have full access to their resource")
	}
}

// TestPlatformAdminBypass tests platform admin bypass.
func TestPlatformAdminBypass(t *testing.T) {
	adminID := uuid.New()
	orgID := uuid.New()

	provider := simple.New(
		simple.WithPlatformAdminBypass(true),
		simple.WithPlatformAdminChecker(func(ctx context.Context, pid uuid.UUID) (bool, error) {
			return pid == adminID, nil
		}),
	)

	principal := authz.NewUserPrincipal(adminID)
	resource := authz.NewOrgResource(authz.ResourceType("resource"), orgID)

	// Platform admin should have access without being a member
	allowed, err := provider.Can(context.Background(), principal, authz.ActionDelete, resource)
	if err != nil {
		t.Fatalf("Can(delete) error: %v", err)
	}
	if !allowed {
		t.Error("Platform admin should bypass permission checks")
	}
}

// TestNonMemberDenied tests that non-members are denied access.
func TestNonMemberDenied(t *testing.T) {
	nonMemberID := uuid.New()
	orgID := uuid.New()

	provider := simple.New(
		simple.WithRoleGetter(func(ctx context.Context, pid, oid uuid.UUID) (string, error) {
			return "", nil // No role = not a member
		}),
	)

	principal := authz.NewUserPrincipal(nonMemberID)
	resource := authz.NewOrgResource(authz.ResourceType("resource"), orgID)

	allowed, err := provider.Can(context.Background(), principal, authz.ActionRead, resource)
	if err != nil {
		t.Fatalf("Can(read) error: %v", err)
	}
	if allowed {
		t.Error("Non-member should be denied access")
	}
}

// TestManagerRolesWithoutGetter verifies that principal resources are
// denied when no manager role getter is configured.
func TestManagerRolesWithoutGetter(t *testing.T) {
	provider := simple.New()
	d, err := provider.Decide(context.Background(), authz.NewUserPrincipal(uuid.New()), authz.PermViewProfile, authz.NewPrincipalResource(uuid.New()))
	if err != nil || d.Allowed || d.Reason == "" {
		t.Errorf("Decide = %+v, %v; want denied with a reason", d, err)
	}
}
