//go:build integration

package spicedb_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/providertest"
	"github.com/plexusone/systemforge/authz/spicedb"
)

// TestIntegration_OrgMembership tests organization membership sync and authorization.
func TestIntegration_OrgMembership(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create embedded SpiceDB client
	client, err := spicedb.NewClient(ctx, spicedb.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("failed to create SpiceDB client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Write base schema
	if err := client.WriteSchema(ctx, spicedb.BaseSchema); err != nil {
		t.Fatalf("failed to write schema: %v", err)
	}

	// Create provider and syncer
	provider := spicedb.NewProvider(client)
	syncer := spicedb.NewSyncer(client)

	// Test data
	ownerID := uuid.New()
	memberID := uuid.New()
	orgID := uuid.New()

	// Test 1: Register organization with owner
	t.Run("RegisterOrganization", func(t *testing.T) {
		if err := syncer.RegisterOrganization(ctx, orgID, ownerID); err != nil {
			t.Fatalf("RegisterOrganization failed: %v", err)
		}

		// Owner should have manage permission
		ownerPrincipal := authz.Principal{ID: ownerID}
		canManage, err := provider.Can(ctx, ownerPrincipal, "manage", authz.Resource{
			Type: "organization",
			ID:   &orgID,
		})
		if err != nil {
			t.Fatalf("Can check failed: %v", err)
		}
		if !canManage {
			t.Error("owner should have manage permission")
		}
	})

	// Test 2: Add member to organization
	t.Run("AddMember", func(t *testing.T) {
		if err := syncer.AddOrgMembership(ctx, memberID, orgID, spicedb.RelMember); err != nil {
			t.Fatalf("AddOrgMembership failed: %v", err)
		}

		memberPrincipal := authz.Principal{ID: memberID}

		// Member should have view permission
		canView, err := provider.Can(ctx, memberPrincipal, "view", authz.Resource{
			Type: "organization",
			ID:   &orgID,
		})
		if err != nil {
			t.Fatalf("Can check failed: %v", err)
		}
		if !canView {
			t.Error("member should have view permission")
		}

		// Members contribute; editing is the editor role's.
		canContribute, err := provider.Can(ctx, memberPrincipal, "contribute", authz.Resource{
			Type: "organization",
			ID:   &orgID,
		})
		if err != nil {
			t.Fatalf("Can check failed: %v", err)
		}
		if !canContribute {
			t.Error("member should have contribute permission")
		}

		// Member should NOT have manage permission
		canManage, err := provider.Can(ctx, memberPrincipal, "manage", authz.Resource{
			Type: "organization",
			ID:   &orgID,
		})
		if err != nil {
			t.Fatalf("Can check failed: %v", err)
		}
		if canManage {
			t.Error("member should NOT have manage permission")
		}
	})

	// Test 3: Update member role to admin
	t.Run("UpdateMemberRole", func(t *testing.T) {
		if err := syncer.UpdateOrgMembership(ctx, memberID, orgID, spicedb.RelMember, spicedb.RelAdmin); err != nil {
			t.Fatalf("UpdateOrgMembership failed: %v", err)
		}

		memberPrincipal := authz.Principal{ID: memberID}

		// Admin should now have manage permission
		canManage, err := provider.Can(ctx, memberPrincipal, "manage", authz.Resource{
			Type: "organization",
			ID:   &orgID,
		})
		if err != nil {
			t.Fatalf("Can check failed: %v", err)
		}
		if !canManage {
			t.Error("admin should have manage permission")
		}
	})

	// Test 4: Remove member from organization
	t.Run("RemoveMember", func(t *testing.T) {
		if err := syncer.RemoveOrgMembership(ctx, memberID, orgID, spicedb.RelAdmin); err != nil {
			t.Fatalf("RemoveOrgMembership failed: %v", err)
		}

		memberPrincipal := authz.Principal{ID: memberID}

		// Member should no longer have view permission
		canView, err := provider.Can(ctx, memberPrincipal, "view", authz.Resource{
			Type: "organization",
			ID:   &orgID,
		})
		if err != nil {
			t.Fatalf("Can check failed: %v", err)
		}
		if canView {
			t.Error("removed member should NOT have view permission")
		}
	})

	// Test 5: Non-member should have no access
	t.Run("NonMemberDenied", func(t *testing.T) {
		nonMemberID := uuid.New()
		nonMemberPrincipal := authz.Principal{ID: nonMemberID}

		canView, err := provider.Can(ctx, nonMemberPrincipal, "view", authz.Resource{
			Type: "organization",
			ID:   &orgID,
		})
		if err != nil {
			t.Fatalf("Can check failed: %v", err)
		}
		if canView {
			t.Error("non-member should NOT have view permission")
		}
	})
}

// TestIntegration_PlatformAdmin tests platform admin permissions.
func TestIntegration_PlatformAdmin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create embedded SpiceDB client
	client, err := spicedb.NewClient(ctx, spicedb.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("failed to create SpiceDB client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Write base schema
	if err := client.WriteSchema(ctx, spicedb.BaseSchema); err != nil {
		t.Fatalf("failed to write schema: %v", err)
	}

	provider := spicedb.NewProvider(client)
	syncer := spicedb.NewSyncer(client)

	adminID := uuid.New()
	regularID := uuid.New()

	// Test 1: Set platform admin
	t.Run("SetPlatformAdmin", func(t *testing.T) {
		if err := syncer.SetPlatformAdmin(ctx, adminID, true); err != nil {
			t.Fatalf("SetPlatformAdmin failed: %v", err)
		}

		adminPrincipal := authz.Principal{ID: adminID}
		isAdmin, err := provider.IsPlatformAdmin(ctx, adminPrincipal)
		if err != nil {
			t.Fatalf("IsPlatformAdmin check failed: %v", err)
		}
		if !isAdmin {
			t.Error("should be platform admin")
		}
	})

	// Test 2: Regular user is not platform admin
	t.Run("NotPlatformAdmin", func(t *testing.T) {
		regularPrincipal := authz.Principal{ID: regularID}
		isAdmin, err := provider.IsPlatformAdmin(ctx, regularPrincipal)
		if err != nil {
			t.Fatalf("IsPlatformAdmin check failed: %v", err)
		}
		if isAdmin {
			t.Error("regular user should NOT be platform admin")
		}
	})

	// Test 3: Revoke platform admin
	t.Run("RevokePlatformAdmin", func(t *testing.T) {
		if err := syncer.SetPlatformAdmin(ctx, adminID, false); err != nil {
			t.Fatalf("SetPlatformAdmin(false) failed: %v", err)
		}

		adminPrincipal := authz.Principal{ID: adminID}
		isAdmin, err := provider.IsPlatformAdmin(ctx, adminPrincipal)
		if err != nil {
			t.Fatalf("IsPlatformAdmin check failed: %v", err)
		}
		if isAdmin {
			t.Error("revoked admin should NOT be platform admin")
		}
	})
}

// TestIntegration_RoleHierarchy tests the role hierarchy in organizations.
func TestIntegration_RoleHierarchy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create embedded SpiceDB client
	client, err := spicedb.NewClient(ctx, spicedb.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("failed to create SpiceDB client: %v", err)
	}
	defer func() { _ = client.Close() }()

	// Write base schema
	if err := client.WriteSchema(ctx, spicedb.BaseSchema); err != nil {
		t.Fatalf("failed to write schema: %v", err)
	}

	provider := spicedb.NewProvider(client)
	syncer := spicedb.NewSyncer(client)

	orgID := uuid.New()
	ownerID := uuid.New()
	adminID := uuid.New()
	memberID := uuid.New()
	viewerID := uuid.New()

	// Setup: Create org with different role members
	_ = syncer.RegisterOrganization(ctx, orgID, ownerID)
	_ = syncer.AddOrgMembership(ctx, adminID, orgID, spicedb.RelAdmin)
	_ = syncer.AddOrgMembership(ctx, memberID, orgID, spicedb.RelMember)
	_ = syncer.AddOrgMembership(ctx, viewerID, orgID, spicedb.RelViewer)

	resource := authz.Resource{Type: "organization", ID: &orgID}

	tests := []struct {
		name       string
		principal  uuid.UUID
		permission string
		expected   bool
	}{
		// Owner permissions
		{"owner_can_manage", ownerID, "manage", true},
		{"owner_can_edit", ownerID, "edit", true},
		{"owner_can_view", ownerID, "view", true},
		{"owner_can_delete", ownerID, "delete", true},

		// Admin permissions
		{"admin_can_manage", adminID, "manage", true},
		{"admin_can_edit", adminID, "edit", true},
		{"admin_can_view", adminID, "view", true},
		{"admin_cannot_delete", adminID, "delete", false},

		// Member permissions
		{"member_cannot_manage", memberID, "manage", false},
		{"member_can_contribute", memberID, "contribute", true},
		{"member_cannot_edit", memberID, "edit", false},
		{"member_can_view", memberID, "view", true},
		{"member_cannot_delete", memberID, "delete", false},

		// Viewer permissions
		{"viewer_cannot_manage", viewerID, "manage", false},
		{"viewer_cannot_edit", viewerID, "edit", false},
		{"viewer_can_view", viewerID, "view", true},
		{"viewer_cannot_delete", viewerID, "delete", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			principal := authz.Principal{ID: tt.principal}
			can, err := provider.Can(ctx, principal, authz.Action(tt.permission), resource)
			if err != nil {
				t.Fatalf("Can check failed: %v", err)
			}
			if can != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, can)
			}
		})
	}
}

// TestIntegration_ManagerRelations runs the manager relation conformance
// case against SpiceDB with relations written by the syncer.
func TestIntegration_ManagerRelations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for name, schema := range map[string]string{"spicedb.BaseSchema": spicedb.BaseSchema, "authz.BaseSpiceDBSchema": authz.BaseSpiceDBSchema} {
		t.Run(name, func(t *testing.T) {
			client, err := spicedb.NewClient(ctx, spicedb.DefaultConfig(), nil)
			if err != nil {
				t.Fatalf("failed to create SpiceDB client: %v", err)
			}
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			})
			if err := client.WriteSchema(ctx, schema); err != nil {
				t.Fatalf("failed to write schema: %v", err)
			}
			syncer := spicedb.NewSyncer(client)

			cfg := providertest.Config{
				Provider: spicedb.NewProvider(client),
				GrantManager: func(t *testing.T, managed, manager uuid.UUID, role string) {
					if err := syncer.AddPrincipalManager(ctx, managed, manager, role); err != nil {
						t.Fatalf("AddPrincipalManager: %v", err)
					}
				},
			}
			providertest.RunManagerRelationTests(t, cfg)

			// Removing the relation revokes the permissions.
			managed, educator := uuid.New(), uuid.New()
			cfg.GrantManager(t, managed, educator, authz.ManagerRoleEducator)
			if err := syncer.RemovePrincipalManager(ctx, managed, educator, authz.ManagerRoleEducator); err != nil {
				t.Fatalf("RemovePrincipalManager: %v", err)
			}
			ok, err := cfg.Provider.Can(ctx, authz.NewUserPrincipal(educator), authz.PermManageCredentials, authz.NewPrincipalResource(managed))
			if err != nil || ok {
				t.Errorf("after removal Can = %v, %v; want false", ok, err)
			}
		})
	}
}

// TestIntegration_OrgPermissions runs the organization permission
// conformance case against SpiceDB, so it agrees with the simple provider.
func TestIntegration_OrgPermissions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := spicedb.NewClient(ctx, spicedb.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("failed to create SpiceDB client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := client.WriteSchema(ctx, authz.BaseSpiceDBSchema); err != nil {
		t.Fatalf("failed to write schema: %v", err)
	}
	syncer := spicedb.NewSyncer(client)
	providertest.RunOrgPermissionTests(t, providertest.Config{
		Provider: spicedb.NewProvider(client),
		GrantOrgRole: func(t *testing.T, org, principal uuid.UUID, role string) {
			if err := syncer.AddOrgMembership(ctx, principal, org, role); err != nil {
				t.Fatalf("AddOrgMembership: %v", err)
			}
		},
	})
}
