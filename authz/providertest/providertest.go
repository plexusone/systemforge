// Package providertest provides conformance tests for authz provider implementations.
//
// This package follows the omnivoice testing pattern with three-tier testing:
//   - Interface tests: Basic interface contract compliance (always run)
//   - Behavior tests: Edge cases and contract guarantees (always run)
//   - Integration tests: Tests requiring external setup (conditional)
//
// Example usage:
//
//	func TestConformance(t *testing.T) {
//	    provider := simple.New()
//	    providertest.RunAll(t, providertest.Config{
//	        Provider: provider,
//	    })
//	}
package providertest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
)

// Config configures the provider test suite.
type Config struct {
	// Provider is the authz.Authorizer implementation to test (required).
	Provider authz.Authorizer

	// OrgProvider is the authz.OrgAuthorizer implementation to test (optional).
	// If nil and Provider implements OrgAuthorizer, Provider will be used.
	OrgProvider authz.OrgAuthorizer

	// PlatformProvider is the authz.PlatformAuthorizer implementation to test (optional).
	// If nil and Provider implements PlatformAuthorizer, Provider will be used.
	PlatformProvider authz.PlatformAuthorizer

	// DecisionProvider is the authz.DecisionAuthorizer implementation to test (optional).
	// If nil and Provider implements DecisionAuthorizer, Provider will be used.
	DecisionProvider authz.DecisionAuthorizer

	// SkipIntegration skips integration tests that may require external setup.
	SkipIntegration bool

	// Timeout for test operations. Default: 30 seconds.
	Timeout time.Duration

	// TestPrincipalID is a UUID for test principals. Default: random UUID.
	TestPrincipalID uuid.UUID

	// TestOrgID is a UUID for test organizations. Default: random UUID.
	TestOrgID uuid.UUID

	// TestResourceID is a UUID for test resources. Default: random UUID.
	TestResourceID uuid.UUID

	// GrantOrgRole, when set, gives principalID a role in orgID, enabling
	// the organization permission tests.
	GrantOrgRole func(t *testing.T, orgID, principalID uuid.UUID, role string)

	// GrantManager, when set, records that managerID manages managedID
	// with a manager role, enabling the manager relation tests (ADR-005).
	GrantManager func(t *testing.T, managedID, managerID uuid.UUID, role string)

	// SetupFunc is called before each test to configure the provider.
	// Use this to set up roles, permissions, etc.
	SetupFunc func(t *testing.T)
}

// withDefaults returns a copy of Config with default values applied.
func (c Config) withDefaults() Config {
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.TestPrincipalID == uuid.Nil {
		c.TestPrincipalID = uuid.New()
	}
	if c.TestOrgID == uuid.Nil {
		c.TestOrgID = uuid.New()
	}
	if c.TestResourceID == uuid.Nil {
		c.TestResourceID = uuid.New()
	}

	// Auto-detect optional interfaces
	if c.OrgProvider == nil {
		if op, ok := c.Provider.(authz.OrgAuthorizer); ok {
			c.OrgProvider = op
		}
	}
	if c.PlatformProvider == nil {
		if pp, ok := c.Provider.(authz.PlatformAuthorizer); ok {
			c.PlatformProvider = pp
		}
	}
	if c.DecisionProvider == nil {
		if dp, ok := c.Provider.(authz.DecisionAuthorizer); ok {
			c.DecisionProvider = dp
		}
	}

	return c
}

// RunAll runs all test tiers: interface, behavior, and integration tests.
func RunAll(t *testing.T, cfg Config) {
	t.Helper()
	cfg = cfg.withDefaults()

	t.Run("Interface", func(t *testing.T) { RunInterfaceTests(t, cfg) })
	t.Run("Behavior", func(t *testing.T) { RunBehaviorTests(t, cfg) })
	t.Run("Integration", func(t *testing.T) { RunIntegrationTests(t, cfg) })
}

// RunInterfaceTests runs basic interface contract compliance tests.
// These tests verify that the provider correctly implements the interfaces.
func RunInterfaceTests(t *testing.T, cfg Config) {
	t.Helper()
	cfg = cfg.withDefaults()

	// Core Authorizer tests
	t.Run("Can_Returns_Bool_And_Error", func(t *testing.T) { testCanReturnsBoolAndError(t, cfg) })
	t.Run("CanAll_Returns_Bool_And_Error", func(t *testing.T) { testCanAllReturnsBoolAndError(t, cfg) })
	t.Run("CanAny_Returns_Bool_And_Error", func(t *testing.T) { testCanAnyReturnsBoolAndError(t, cfg) })
	t.Run("Filter_Returns_Slice_And_Error", func(t *testing.T) { testFilterReturnsSliceAndError(t, cfg) })

	// OrgAuthorizer tests (if implemented)
	if cfg.OrgProvider != nil {
		t.Run("CanForOrg_Returns_Bool_And_Error", func(t *testing.T) { testCanForOrgReturnsBoolAndError(t, cfg) })
		t.Run("GetRole_Returns_String_And_Error", func(t *testing.T) { testGetRoleReturnsStringAndError(t, cfg) })
		t.Run("IsMember_Returns_Bool_And_Error", func(t *testing.T) { testIsMemberReturnsBoolAndError(t, cfg) })
	}

	// PlatformAuthorizer tests (if implemented)
	if cfg.PlatformProvider != nil {
		t.Run("IsPlatformAdmin_Returns_Bool_And_Error", func(t *testing.T) { testIsPlatformAdminReturnsBoolAndError(t, cfg) })
	}

	// DecisionAuthorizer tests (if implemented)
	if cfg.DecisionProvider != nil {
		t.Run("Decide_Returns_Decision_And_Error", func(t *testing.T) { testDecideReturnsDecisionAndError(t, cfg) })
	}
}

// RunBehaviorTests runs edge case and contract guarantee tests.
func RunBehaviorTests(t *testing.T, cfg Config) {
	t.Helper()
	cfg = cfg.withDefaults()

	t.Run("Context_Cancellation", func(t *testing.T) { testContextCancellation(t, cfg) })
	t.Run("CanAll_Empty_Actions", func(t *testing.T) { testCanAllEmptyActions(t, cfg) })
	t.Run("CanAny_Empty_Actions", func(t *testing.T) { testCanAnyEmptyActions(t, cfg) })
	t.Run("Filter_Empty_Resources", func(t *testing.T) { testFilterEmptyResources(t, cfg) })
	t.Run("Filter_All_Denied", func(t *testing.T) { testFilterAllDenied(t, cfg) })
}

// RunIntegrationTests runs tests that may require external setup.
func RunIntegrationTests(t *testing.T, cfg Config) {
	t.Helper()
	cfg = cfg.withDefaults()

	if cfg.SkipIntegration {
		t.Skip("integration tests skipped")
	}

	t.Run("Owner_Has_Full_Access", func(t *testing.T) { testOwnerHasFullAccess(t, cfg) })
	t.Run("Non_Member_Denied", func(t *testing.T) { testNonMemberDenied(t, cfg) })

	if cfg.PlatformProvider != nil {
		t.Run("Platform_Admin_Bypass", func(t *testing.T) { testPlatformAdminBypass(t, cfg) })
	}

	if cfg.DecisionProvider != nil {
		t.Run("Decide_Returns_Reason", func(t *testing.T) { testDecideReturnsReason(t, cfg) })
	}

	if cfg.GrantManager != nil {
		RunManagerRelationTests(t, cfg)
	}
	if cfg.GrantOrgRole != nil {
		RunOrgPermissionTests(t, cfg)
	}
}

// RunOrgPermissionTests checks every base organization permission for
// every organization role and for a non-member, so providers agree with
// authz.OrgRolePermissions and the base SpiceDB schema. It requires
// cfg.GrantOrgRole.
func RunOrgPermissionTests(t *testing.T, cfg Config) {
	t.Helper()
	cfg = cfg.withDefaults()
	if cfg.GrantOrgRole == nil {
		t.Fatal("providertest: RunOrgPermissionTests requires Config.GrantOrgRole")
	}
	t.Run("Org_Permissions", func(t *testing.T) { testOrgPermissions(t, cfg) })
}

// RunManagerRelationTests checks the guardian and educator permissions on
// principal resources (ADR-005). It requires cfg.GrantManager and can run
// on its own against providers, such as SpiceDB, whose other integration
// cases need a matching schema.
func RunManagerRelationTests(t *testing.T, cfg Config) {
	t.Helper()
	cfg = cfg.withDefaults()
	if cfg.GrantManager == nil {
		t.Fatal("providertest: RunManagerRelationTests requires Config.GrantManager")
	}
	t.Run("Manager_Relations", func(t *testing.T) { testManagerRelations(t, cfg) })
}

// Interface Tests

func testCanReturnsBoolAndError(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)
	resource := authz.NewResource("test")

	allowed, err := cfg.Provider.Can(ctx, principal, authz.ActionRead, resource)

	// We don't check the actual value, just that it returns without panic
	_ = allowed
	_ = err
}

func testCanAllReturnsBoolAndError(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)
	resource := authz.NewResource("test")
	actions := []authz.Action{authz.ActionRead, authz.ActionUpdate}

	allowed, err := cfg.Provider.CanAll(ctx, principal, actions, resource)
	_ = allowed
	_ = err
}

func testCanAnyReturnsBoolAndError(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)
	resource := authz.NewResource("test")
	actions := []authz.Action{authz.ActionRead, authz.ActionUpdate}

	allowed, err := cfg.Provider.CanAny(ctx, principal, actions, resource)
	_ = allowed
	_ = err
}

func testFilterReturnsSliceAndError(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)
	resources := []authz.Resource{
		authz.NewResource("test1"),
		authz.NewResource("test2"),
	}

	filtered, err := cfg.Provider.Filter(ctx, principal, authz.ActionRead, resources)
	// We just verify it returns without panic - nil slice is acceptable in Go
	_ = filtered
	_ = err
}

func testCanForOrgReturnsBoolAndError(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)
	resource := authz.NewResource("test")

	allowed, err := cfg.OrgProvider.CanForOrg(ctx, principal, cfg.TestOrgID, authz.ActionRead, resource)
	_ = allowed
	_ = err
}

func testGetRoleReturnsStringAndError(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)

	role, err := cfg.OrgProvider.GetRole(ctx, principal, cfg.TestOrgID)
	_ = role
	_ = err
}

func testIsMemberReturnsBoolAndError(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)

	isMember, err := cfg.OrgProvider.IsMember(ctx, principal, cfg.TestOrgID)
	_ = isMember
	_ = err
}

func testIsPlatformAdminReturnsBoolAndError(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)

	isAdmin, err := cfg.PlatformProvider.IsPlatformAdmin(ctx, principal)
	_ = isAdmin
	_ = err
}

func testDecideReturnsDecisionAndError(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)
	resource := authz.NewResource("test")

	decision, err := cfg.DecisionProvider.Decide(ctx, principal, authz.ActionRead, resource)
	_ = decision.Allowed
	_ = decision.Reason
	_ = err
}

// Behavior Tests

func testContextCancellation(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)
	resource := authz.NewResource("test")

	_, err := cfg.Provider.Can(ctx, principal, authz.ActionRead, resource)

	// Provider should either return context error or handle gracefully
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Logf("Can() with cancelled context returned: %v (expected context.Canceled or graceful handling)", err)
	}
}

func testCanAllEmptyActions(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)
	resource := authz.NewResource("test")

	// Empty actions should return true (vacuous truth)
	allowed, err := cfg.Provider.CanAll(ctx, principal, []authz.Action{}, resource)
	if err != nil {
		t.Fatalf("CanAll() with empty actions returned error: %v", err)
	}
	if !allowed {
		t.Error("CanAll() with empty actions should return true (vacuous truth)")
	}
}

func testCanAnyEmptyActions(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)
	resource := authz.NewResource("test")

	// Empty actions should return false (no actions to match)
	allowed, err := cfg.Provider.CanAny(ctx, principal, []authz.Action{}, resource)
	if err != nil {
		t.Fatalf("CanAny() with empty actions returned error: %v", err)
	}
	if allowed {
		t.Error("CanAny() with empty actions should return false")
	}
}

func testFilterEmptyResources(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)

	filtered, err := cfg.Provider.Filter(ctx, principal, authz.ActionRead, []authz.Resource{})
	if err != nil {
		t.Fatalf("Filter() with empty resources returned error: %v", err)
	}
	if len(filtered) != 0 {
		t.Errorf("Filter() with empty resources returned %d items, expected 0", len(filtered))
	}
}

func testFilterAllDenied(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// Use a principal that has no permissions
	principal := authz.NewUserPrincipal(uuid.New())
	resources := []authz.Resource{
		authz.NewOrgResource("test", uuid.New()),
		authz.NewOrgResource("test", uuid.New()),
	}

	filtered, err := cfg.Provider.Filter(ctx, principal, authz.ActionDelete, resources)
	if err != nil {
		t.Fatalf("Filter() returned error: %v", err)
	}
	if len(filtered) != 0 {
		t.Errorf("Filter() returned %d items for unauthorized principal, expected 0", len(filtered))
	}
}

// Integration Tests

func testOwnerHasFullAccess(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	ownerID := cfg.TestPrincipalID
	principal := authz.NewUserPrincipal(ownerID)
	resource := authz.NewOwnedResource("test", cfg.TestResourceID, ownerID)

	// Owner should have access to delete their own resource
	allowed, err := cfg.Provider.Can(ctx, principal, authz.ActionDelete, resource)
	if err != nil {
		t.Fatalf("Can() returned error: %v", err)
	}
	if !allowed {
		t.Error("Owner should have full access to their own resource")
	}
}

func testNonMemberDenied(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// Use a principal that is not a member of the org
	principal := authz.NewUserPrincipal(uuid.New())
	resource := authz.NewOrgResource("test", cfg.TestOrgID)

	allowed, err := cfg.Provider.Can(ctx, principal, authz.ActionRead, resource)
	if err != nil {
		t.Fatalf("Can() returned error: %v", err)
	}
	if allowed {
		t.Error("Non-member should be denied access to org resource")
	}
}

func testPlatformAdminBypass(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)

	// First check if principal is a platform admin
	isAdmin, err := cfg.PlatformProvider.IsPlatformAdmin(ctx, principal)
	if err != nil {
		t.Fatalf("IsPlatformAdmin() returned error: %v", err)
	}

	if !isAdmin {
		t.Skip("Test principal is not a platform admin, skipping bypass test")
	}

	// Platform admin should have access to any resource
	resource := authz.NewOrgResource("test", uuid.New())
	allowed, err := cfg.Provider.Can(ctx, principal, authz.ActionDelete, resource)
	if err != nil {
		t.Fatalf("Can() returned error: %v", err)
	}
	if !allowed {
		t.Error("Platform admin should bypass all permission checks")
	}
}

func testDecideReturnsReason(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	principal := authz.NewUserPrincipal(cfg.TestPrincipalID)
	resource := authz.NewResource("test")

	decision, err := cfg.DecisionProvider.Decide(ctx, principal, authz.ActionRead, resource)
	if err != nil {
		t.Fatalf("Decide() returned error: %v", err)
	}

	if decision.Reason == "" {
		t.Error("Decide() should return a reason for the decision")
	}
}

func testManagerRelations(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	managed := uuid.New()
	guardian := uuid.New()
	educator := uuid.New()
	stranger := uuid.New()
	cfg.GrantManager(t, managed, guardian, authz.ManagerRoleGuardian)
	cfg.GrantManager(t, managed, educator, authz.ManagerRoleEducator)

	all := []authz.Action{authz.PermManageAccount, authz.PermManageCredentials, authz.PermViewProfile, authz.PermManageManagers}
	for _, tc := range []struct {
		name    string
		subject uuid.UUID
		allowed []authz.Action
	}{
		{"guardian", guardian, all},
		{"educator", educator, []authz.Action{authz.PermManageCredentials, authz.PermViewProfile}},
		{"stranger", stranger, nil},
		{"self", managed, nil},
	} {
		for _, action := range all {
			want := false
			for _, a := range tc.allowed {
				want = want || a == action
			}
			got, err := cfg.Provider.Can(ctx, authz.NewUserPrincipal(tc.subject), action, authz.NewPrincipalResource(managed))
			if err != nil {
				t.Fatalf("Can(%s, %s): %v", tc.name, action, err)
			}
			if got != want {
				t.Errorf("Can(%s, %s) = %v, want %v", tc.name, action, got, want)
			}
		}
	}

	// A relation over one principal grants nothing over another.
	got, err := cfg.Provider.Can(ctx, authz.NewUserPrincipal(guardian), authz.PermViewProfile, authz.NewPrincipalResource(uuid.New()))
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if got {
		t.Error("guardian of one principal can view another's profile")
	}
}

func testOrgPermissions(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	org := uuid.New()
	members := map[string]uuid.UUID{}
	for role := range authz.OrgRolePermissions {
		members[role] = uuid.New()
		cfg.GrantOrgRole(t, org, members[role], role)
	}
	members["non-member"] = uuid.New()
	resource := authz.NewResourceWithID(authz.ResourceTypeOrganization, org)

	for who, id := range members {
		for _, action := range authz.OrgRolePermissions["owner"] {
			want := authz.OrgRoleAllows(who, action)
			got, err := cfg.Provider.Can(ctx, authz.NewUserPrincipal(id), action, resource)
			if err != nil {
				t.Fatalf("Can(%s, %s): %v", who, action, err)
			}
			if got != want {
				t.Errorf("Can(%s, %s) = %v, want %v", who, action, got, want)
			}
		}
		if cfg.OrgProvider != nil {
			role, err := cfg.OrgProvider.GetRole(ctx, authz.NewUserPrincipal(id), org)
			if err != nil {
				t.Fatalf("GetRole(%s): %v", who, err)
			}
			want := who
			if who == "non-member" {
				want = ""
			}
			if role != want {
				t.Errorf("GetRole(%s) = %q, want %q", who, role, want)
			}
		}
	}

	// A role in one organization grants nothing in another.
	other := authz.NewResourceWithID(authz.ResourceTypeOrganization, uuid.New())
	if got, err := cfg.Provider.Can(ctx, authz.NewUserPrincipal(members["owner"]), authz.PermOrgView, other); err != nil || got {
		t.Errorf("owner of one organization views another = %v, %v", got, err)
	}
}
