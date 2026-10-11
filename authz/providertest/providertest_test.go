package providertest

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
)

// TestRunAll_MockProvider verifies the test suite works correctly with the mock.
func TestRunAll_MockProvider(t *testing.T) {
	mock := NewMockProvider()

	// Set up some test data
	principalID := uuid.New()
	orgID := uuid.New()
	mock.SetRole(principalID, orgID, "admin")

	RunAll(t, Config{
		Provider:        mock,
		SkipIntegration: false,
		TestPrincipalID: principalID,
		TestOrgID:       orgID,
	})
}

// TestInterfaceTests_MockProvider verifies interface tests pass with the mock.
func TestInterfaceTests_MockProvider(t *testing.T) {
	mock := NewMockProvider()

	RunInterfaceTests(t, Config{
		Provider: mock,
	})
}

// TestBehaviorTests_MockProvider verifies behavior tests pass with the mock.
func TestBehaviorTests_MockProvider(t *testing.T) {
	mock := NewMockProvider()

	RunBehaviorTests(t, Config{
		Provider: mock,
	})
}

// TestMockProvider_InterfaceConformance verifies MockProvider implements all interfaces.
func TestMockProvider_InterfaceConformance(t *testing.T) {
	mock := NewMockProvider()

	// Verify interface implementation via type assertions
	var _ authz.Authorizer = mock
	var _ authz.OrgAuthorizer = mock
	var _ authz.PlatformAuthorizer = mock
	var _ authz.DecisionAuthorizer = mock
}

// TestMockProvider_Name returns the provider name.
func TestMockProvider_Name(t *testing.T) {
	mock := NewMockProvider()

	name := mock.Name()
	if name != "mock" {
		t.Errorf("Name() = %q, want %q", name, "mock")
	}

	// Verify name follows naming convention (lowercase alphanumeric)
	for _, r := range name {
		isLowerAlpha := r >= 'a' && r <= 'z'
		isDigit := r >= '0' && r <= '9'
		isAllowed := isLowerAlpha || isDigit || r == '-' || r == '_'
		if !isAllowed {
			t.Errorf("Name() contains invalid character %q; should be lowercase alphanumeric with hyphens/underscores", r)
		}
	}
}

// TestMockProvider_SetRole sets and gets roles correctly.
func TestMockProvider_SetRole(t *testing.T) {
	mock := NewMockProvider()

	principalID := uuid.New()
	orgID := uuid.New()
	mock.SetRole(principalID, orgID, "admin")

	principal := authz.NewUserPrincipal(principalID)
	role, err := mock.GetRole(context.Background(), principal, orgID)
	if err != nil {
		t.Fatalf("GetRole() error: %v", err)
	}
	if role != "admin" {
		t.Errorf("GetRole() = %q, want %q", role, "admin")
	}
}

// TestMockProvider_SetPlatformAdmin sets platform admin status correctly.
func TestMockProvider_SetPlatformAdmin(t *testing.T) {
	mock := NewMockProvider()

	principalID := uuid.New()
	mock.SetPlatformAdmin(principalID, true)

	principal := authz.NewUserPrincipal(principalID)
	isAdmin, err := mock.IsPlatformAdmin(context.Background(), principal)
	if err != nil {
		t.Fatalf("IsPlatformAdmin() error: %v", err)
	}
	if !isAdmin {
		t.Error("IsPlatformAdmin() = false, want true")
	}
}

// TestMockProvider_ContextCancellation respects context cancellation.
func TestMockProvider_ContextCancellation(t *testing.T) {
	mock := NewMockProvider()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	principal := authz.NewUserPrincipal(uuid.New())
	resource := authz.NewResource("test")

	_, err := mock.Can(ctx, principal, authz.ActionRead, resource)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Can() with cancelled context = %v, want context.Canceled", err)
	}
}

// TestMockProvider_OwnerAccess grants full access to resource owners.
func TestMockProvider_OwnerAccess(t *testing.T) {
	mock := NewMockProvider()

	ownerID := uuid.New()
	principal := authz.NewUserPrincipal(ownerID)
	resource := authz.NewOwnedResource("test", uuid.New(), ownerID)

	allowed, err := mock.Can(context.Background(), principal, authz.ActionDelete, resource)
	if err != nil {
		t.Fatalf("Can() error: %v", err)
	}
	if !allowed {
		t.Error("Can() = false for owner, want true")
	}
}

// TestMockProvider_PlatformAdminBypass grants access to platform admins.
func TestMockProvider_PlatformAdminBypass(t *testing.T) {
	mock := NewMockProvider()

	adminID := uuid.New()
	mock.SetPlatformAdmin(adminID, true)

	principal := authz.NewUserPrincipal(adminID)
	resource := authz.NewOrgResource("test", uuid.New())

	allowed, err := mock.Can(context.Background(), principal, authz.ActionDelete, resource)
	if err != nil {
		t.Fatalf("Can() error: %v", err)
	}
	if !allowed {
		t.Error("Can() = false for platform admin, want true")
	}
}

// TestMockProvider_RolePermissions checks role-based permissions.
func TestMockProvider_RolePermissions(t *testing.T) {
	mock := NewMockProvider()

	principalID := uuid.New()
	orgID := uuid.New()
	mock.SetRole(principalID, orgID, "member")

	principal := authz.NewUserPrincipal(principalID)
	resource := authz.NewOrgResource(authz.ResourceType("resource"), orgID)

	// Member should have read access
	allowed, err := mock.Can(context.Background(), principal, authz.ActionRead, resource)
	if err != nil {
		t.Fatalf("Can(read) error: %v", err)
	}
	if !allowed {
		t.Error("Can(read) = false for member, want true")
	}

	// Member should NOT have delete access
	allowed, err = mock.Can(context.Background(), principal, authz.ActionDelete, resource)
	if err != nil {
		t.Fatalf("Can(delete) error: %v", err)
	}
	if allowed {
		t.Error("Can(delete) = true for member, want false")
	}
}

// TestMockProvider_Decide returns decision with reason.
func TestMockProvider_Decide(t *testing.T) {
	mock := NewMockProvider()

	principalID := uuid.New()
	orgID := uuid.New()
	mock.SetRole(principalID, orgID, "admin")

	principal := authz.NewUserPrincipal(principalID)
	resource := authz.NewOrgResource(authz.ResourceType("resource"), orgID)

	decision, err := mock.Decide(context.Background(), principal, authz.ActionRead, resource)
	if err != nil {
		t.Fatalf("Decide() error: %v", err)
	}
	if !decision.Allowed {
		t.Error("Decide().Allowed = false, want true")
	}
	if decision.Reason == "" {
		t.Error("Decide().Reason is empty, want non-empty")
	}
}

// TestMockProvider_CustomCanFunc allows custom Can behavior.
func TestMockProvider_CustomCanFunc(t *testing.T) {
	mock := NewMockProvider()
	mock.CanFunc = func(ctx context.Context, principal authz.Principal, action authz.Action, resource authz.Resource) (bool, error) {
		return action == authz.ActionRead, nil
	}

	principal := authz.NewUserPrincipal(uuid.New())
	resource := authz.NewResource("test")

	// Custom func allows read
	allowed, _ := mock.Can(context.Background(), principal, authz.ActionRead, resource)
	if !allowed {
		t.Error("Can(read) with custom func = false, want true")
	}

	// Custom func denies write
	allowed, _ = mock.Can(context.Background(), principal, authz.ActionUpdate, resource)
	if allowed {
		t.Error("Can(update) with custom func = true, want false")
	}
}
