package rbac

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
)

// ErrNoResourceGrants is returned by the grant operations of a Provider
// built without WithResourceGrants.
var ErrNoResourceGrants = errors.New("rbac: resource grants are not configured (use WithResourceGrants)")

// GrantResourceRole gives the principal a role on the resource through the
// configured grant store. Granting to a principal with no membership in the
// resource's organization adds a collaborator membership.
func (a *Provider) GrantResourceRole(ctx context.Context, principalID uuid.UUID, resource authz.ResourceRef, role string, grantedBy uuid.UUID) error {
	if a.grants == nil {
		return ErrNoResourceGrants
	}
	return a.grants.GrantResourceRole(ctx, principalID, resource, role, grantedBy)
}

// RevokeResourceRole removes the principal's grant on the resource;
// revoking a collaborator's last grant removes the membership.
func (a *Provider) RevokeResourceRole(ctx context.Context, principalID uuid.UUID, resource authz.ResourceRef) error {
	if a.grants == nil {
		return ErrNoResourceGrants
	}
	return a.grants.RevokeResourceRole(ctx, principalID, resource)
}

// ListResourceGrants lists the grants on one resource, highest role first.
func (a *Provider) ListResourceGrants(ctx context.Context, resource authz.ResourceRef) ([]authz.Grant, error) {
	if a.grants == nil {
		return nil, ErrNoResourceGrants
	}
	return a.grants.ListResourceGrants(ctx, resource)
}

// ListResources returns what the principal may access of resourceType with
// permission (view, edit or manage), in two parts an application applies as
// `organization_id IN (OrganizationIDs) OR id IN (IDs)`:
//
//   - IDs are the resources the principal holds a direct grant on whose
//     role grants the permission, in organizations where its membership is
//     active;
//   - OrganizationIDs are the organizations in which the principal's
//     organization role grants "{resourceType}.{permission}" in the
//     provider's permission map, which makes the permission hold on every
//     resource of the type there.
//
// The platform-admin bypass and resource ownership of Can are not part of
// the answer: an administrator or owner is not enumerated here.
func (a *Provider) ListResources(ctx context.Context, principalID uuid.UUID, resourceType string, permission authz.Action) (authz.ResourceSet, error) {
	if a.grants == nil {
		return authz.ResourceSet{}, ErrNoResourceGrants
	}
	set, err := a.grants.ListResources(ctx, principalID, resourceType, permission)
	if err != nil {
		return authz.ResourceSet{}, err
	}
	roles, err := a.grants.OrganizationRoles(ctx, principalID)
	if err != nil {
		return authz.ResourceSet{}, fmt.Errorf("listing organization roles: %w", err)
	}
	want := buildPermission(authz.ResourceType(resourceType), permission)
	for orgID, role := range roles {
		if a.permissions.HasPermission(role, want) {
			set.OrganizationIDs = append(set.OrganizationIDs, orgID)
		}
	}
	slices.SortFunc(set.OrganizationIDs, func(x, y uuid.UUID) int { return slices.Compare(x[:], y[:]) })
	return set, nil
}

// Verify Provider implements the grant contract.
var _ authz.ResourceGranter = (*Provider)(nil)
