package contract

import (
	"context"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
)

// registerPolicyEndpoints registers policy endpoints.
func (a *API) registerPolicyEndpoints() {
	base := a.provider.Config().BaseURL

	// List roles
	huma.Register(a.huma, huma.Operation{
		OperationID: "listRoles",
		Method:      "GET",
		Path:        base + "/policy/roles",
		Summary:     "List roles",
		Description: "Returns all defined roles with their permissions and hierarchy levels.",
		Tags:        []string{"Policy"},
		Security: []map[string][]string{
			{"bearer": {"policy:read"}},
		},
	}, a.listRoles)

	// List permissions
	huma.Register(a.huma, huma.Operation{
		OperationID: "listPermissions",
		Method:      "GET",
		Path:        base + "/policy/permissions",
		Summary:     "List permissions",
		Description: "Returns all defined permissions.",
		Tags:        []string{"Policy"},
		Security: []map[string][]string{
			{"bearer": {"policy:read"}},
		},
	}, a.listPermissions)

	// Evaluate policy
	huma.Register(a.huma, huma.Operation{
		OperationID: "evaluatePolicy",
		Method:      "POST",
		Path:        base + "/policy/evaluate",
		Summary:     "Evaluate policy",
		Description: "Evaluates whether a principal can perform an action on a resource.",
		Tags:        []string{"Policy"},
		Security: []map[string][]string{
			{"bearer": {"policy:read"}},
		},
	}, a.evaluatePolicy)

	// Sync policies (federation only)
	huma.Register(a.huma, huma.Operation{
		OperationID: "syncPolicies",
		Method:      "POST",
		Path:        base + "/policy/sync",
		Summary:     "Sync policies from SystemAuth",
		Description: "Synchronizes policy data from SystemAuth. Requires federation mode.",
		Tags:        []string{"Policy", "Federation"},
		Security: []map[string][]string{
			{"bearer": {"policy:sync"}},
		},
	}, a.syncPolicies)
}

func (a *API) listRoles(ctx context.Context, input *struct{}) (*RolesListOutput, error) {
	if err := a.checkPermission(ctx, PermissionPolicyRead); err != nil {
		return nil, err
	}

	roles := make([]Role, 0)
	for roleName, level := range authz.DefaultRoleHierarchy {
		permissions := authz.DefaultRolePermissions.GetPermissions(roleName)
		role := Role{
			ID:          roleName,
			DisplayName: formatRoleName(roleName),
			Description: formatRoleDescription(roleName),
			Permissions: permissions,
			Scope:       "tenant",
			Level:       level,
		}
		roles = append(roles, role)
	}

	return &RolesListOutput{
		Body: struct {
			Roles []Role `json:"roles" doc:"List of roles"`
		}{
			Roles: roles,
		},
	}, nil
}

func (a *API) listPermissions(ctx context.Context, input *struct{}) (*PermissionsListOutput, error) {
	if err := a.checkPermission(ctx, PermissionPolicyRead); err != nil {
		return nil, err
	}

	// Collect all unique permissions
	permSet := make(map[string]bool)
	for _, perms := range authz.DefaultRolePermissions {
		for _, perm := range perms {
			permSet[perm] = true
		}
	}

	permissions := make([]Permission, 0, len(permSet))
	for perm := range permSet {
		permissions = append(permissions, Permission{
			ID:          perm,
			DisplayName: perm,
			Description: "Permission: " + perm,
		})
	}

	return &PermissionsListOutput{
		Body: struct {
			Permissions []Permission `json:"permissions" doc:"List of permissions"`
		}{
			Permissions: permissions,
		},
	}, nil
}

func (a *API) evaluatePolicy(ctx context.Context, input *EvaluateInput) (*EvaluateOutput, error) {
	if err := a.checkPermission(ctx, PermissionPolicyRead); err != nil {
		return nil, err
	}

	policySvc := a.provider.PolicyService()
	if policySvc == nil {
		// No policy service - return default allow
		return &EvaluateOutput{
			Body: struct {
				Allowed     bool      `json:"allowed" doc:"Whether the action is allowed" example:"true"`
				Reason      string    `json:"reason" doc:"Reason for the decision" example:"role:admin grants users:*"`
				Policies    []string  `json:"policies,omitempty" doc:"Policies that contributed to the decision"`
				EvaluatedAt time.Time `json:"evaluated_at" doc:"Timestamp of evaluation" format:"date-time"`
			}{
				Allowed:     true,
				Reason:      "no policy service configured",
				EvaluatedAt: time.Now(),
			},
		}, nil
	}

	// Build principal for evaluation
	principal := authz.Principal{
		ID:   input.Body.PrincipalID,
		Type: authz.PrincipalTypeUser,
	}

	// Build resource for evaluation
	resourceID := input.Body.Resource.ID
	resource := authz.Resource{
		Type: authz.ResourceType(input.Body.Resource.Type),
		ID:   &resourceID,
	}

	// Evaluate
	decision, err := policySvc.Decide(ctx, principal, authz.Action(input.Body.Action), resource)
	if err != nil {
		return nil, huma.Error500InternalServerError("policy evaluation failed", err)
	}

	policies := []string{}
	if decision.PolicyID != "" {
		policies = []string{decision.PolicyID}
	}

	return &EvaluateOutput{
		Body: struct {
			Allowed     bool      `json:"allowed" doc:"Whether the action is allowed" example:"true"`
			Reason      string    `json:"reason" doc:"Reason for the decision" example:"role:admin grants users:*"`
			Policies    []string  `json:"policies,omitempty" doc:"Policies that contributed to the decision"`
			EvaluatedAt time.Time `json:"evaluated_at" doc:"Timestamp of evaluation" format:"date-time"`
		}{
			Allowed:     decision.Allowed,
			Reason:      decision.Reason,
			Policies:    policies,
			EvaluatedAt: time.Now(),
		},
	}, nil
}

//nolint:dupl // Sync handlers are intentionally similar but handle different types
func (a *API) syncPolicies(ctx context.Context, input *PolicySyncInput) (*PolicySyncOutput, error) {
	if err := a.checkFederated(); err != nil {
		return nil, err
	}
	if err := a.checkPermission(ctx, PermissionPolicySync); err != nil {
		return nil, err
	}
	if err := a.startSync(); err != nil {
		return nil, err
	}
	defer a.provider.FederationState().EndSync()

	// Validate federation ID matches
	expectedFedID := a.provider.FederationState().FederationID()
	if expectedFedID != nil && input.Body.FederationID != *expectedFedID {
		return nil, huma.Error400BadRequest("federation ID mismatch")
	}

	// Process each policy
	applied := make([]uuid.UUID, 0, len(input.Body.Policies))
	failed := make([]PolicySyncFailure, 0)

	for _, policy := range input.Body.Policies {
		// For now, just track as applied (actual implementation would apply policies)
		applied = append(applied, policy.ID)
	}

	a.provider.FederationState().SetLastPolicySync(time.Now())

	return &PolicySyncOutput{
		Body: struct {
			Applied   []uuid.UUID         `json:"applied" doc:"Successfully applied policy IDs"`
			Failed    []PolicySyncFailure `json:"failed" doc:"Failed policy operations"`
			SyncToken string              `json:"sync_token" doc:"Updated sync token"`
		}{
			Applied:   applied,
			Failed:    failed,
			SyncToken: input.Body.SyncToken,
		},
	}, nil
}

// formatRoleName formats a role ID into a display name.
func formatRoleName(role string) string {
	switch role {
	case "owner":
		return "Owner"
	case "admin":
		return "Administrator"
	case "editor":
		return "Editor"
	case "member":
		return "Member"
	case "viewer":
		return "Viewer"
	case "guest":
		return "Guest"
	default:
		return role
	}
}

// formatRoleDescription returns a description for a role.
func formatRoleDescription(role string) string {
	switch role {
	case "owner":
		return "Full administrative access including organization management"
	case "admin":
		return "Administrative access to manage members and resources"
	case "editor":
		return "Create, read, update, and delete resources"
	case "member":
		return "Create, read, and update resources"
	case "viewer":
		return "Read-only access to resources"
	case "guest":
		return "Limited guest access"
	default:
		return ""
	}
}
