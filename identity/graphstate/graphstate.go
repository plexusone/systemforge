// Package graphstate decides which relationships of the authorization
// graph the identity tables call for.
//
// The identity services ask it before writing a relationship a committed
// change granted, inside a transaction holding the graph locks
// (graphlock.Grant), and the graph reconciler (authz/mode) builds its
// desired set from the same predicates. A grant written after its commit
// and a repair therefore agree on what access a principal holds, and
// neither writes access a revocation has removed in the meantime.
//
// The rules:
//
//   - Only an active principal holds access. A deactivated principal's
//     memberships, application roles, resource grants, platform
//     administration and manager relations stay in the tables but call for
//     no relationship until the principal is reactivated.
//   - A membership calls for organization:{org}#{role} while it is active
//     and its organization is active.
//   - An application role calls for {app}_org:{org}#{role} while the
//     principal holds an active owner, admin or member membership of the
//     organization. Collaborators hold no application roles.
//   - A resource grant calls for {type}:{id}#{role} while the principal
//     holds an active membership, of any role, of the grant's
//     organization.
//   - Platform administration calls for platform:global#admin.
//   - A manager relationship calls for
//     principal:{managed}#{role}@principal:{manager} while it is active and
//     the manager is active.
package graphstate

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/approle"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/resourcegrant"
)

// Membership roles.
const (
	RoleOwner        = "owner"
	RoleAdmin        = "admin"
	RoleMember       = "member"
	RoleCollaborator = "collaborator"
)

// OrgRoles returns the membership roles that hold a relation on the
// organization.
func OrgRoles() []string {
	return []string{RoleOwner, RoleAdmin, RoleMember, RoleCollaborator}
}

// AppRoleHolders returns the membership roles that may hold application
// roles.
func AppRoleHolders() []string {
	return []string{RoleOwner, RoleAdmin, RoleMember}
}

// CanHoldAppRoles reports whether a membership role may hold application
// roles.
func CanHoldAppRoles(role string) bool {
	return slices.Contains(AppRoleHolders(), role)
}

// activePrincipal selects active principals.
func activePrincipal() predicate.Principal { return principal.Active(true) }

// HoldingMemberships returns the predicates of the memberships that call
// for access with one of roles, every organization role when none is
// given: active, of an active organization, held by an active principal.
func HoldingMemberships(roles ...string) []predicate.PrincipalMembership {
	if len(roles) == 0 {
		roles = OrgRoles()
	}
	return []predicate.PrincipalMembership{
		principalmembership.Active(true),
		principalmembership.RoleIn(roles...),
		principalmembership.HasOrganizationWith(organization.Active(true)),
		principalmembership.HasPrincipalWith(activePrincipal()),
	}
}

// Membership reports whether principalID's membership of orgID calls for
// access with one of roles (any organization role when none is given).
func Membership(ctx context.Context, c *ent.Client, orgID, principalID uuid.UUID, roles ...string) (bool, error) {
	ok, err := c.PrincipalMembership.Query().
		Where(principalmembership.OrganizationID(orgID), principalmembership.PrincipalID(principalID)).
		Where(HoldingMemberships(roles...)...).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("graphstate: reading membership: %w", err)
	}
	return ok, nil
}

// AppRole reports whether the tables call for principalID holding role in
// application for orgID: the stored role, held through a membership that
// may hold application roles.
func AppRole(ctx context.Context, c *ent.Client, orgID, principalID uuid.UUID, application, role string) (bool, error) {
	held, err := c.AppRole.Query().
		Where(
			approle.OrganizationID(orgID),
			approle.PrincipalID(principalID),
			approle.Application(application),
			approle.Role(role),
		).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("graphstate: reading application role: %w", err)
	}
	if !held {
		return false, nil
	}
	return Membership(ctx, c, orgID, principalID, AppRoleHolders()...)
}

// ResourceGrant reports whether the tables call for principalID holding
// role on the resource: a grant of that role in orgID, held through a
// membership of orgID.
func ResourceGrant(ctx context.Context, c *ent.Client, orgID, principalID uuid.UUID, resourceType, resourceID, role string) (bool, error) {
	held, err := c.ResourceGrant.Query().
		Where(
			resourcegrant.OrganizationID(orgID),
			resourcegrant.PrincipalID(principalID),
			resourcegrant.ResourceType(resourceType),
			resourcegrant.ResourceID(resourceID),
			resourcegrant.Role(role),
		).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("graphstate: reading resource grant: %w", err)
	}
	if !held {
		return false, nil
	}
	return Membership(ctx, c, orgID, principalID)
}

// HoldingAdmins returns the predicates of the humans whose platform
// administration calls for access.
func HoldingAdmins() []predicate.Human {
	return []predicate.Human{human.IsPlatformAdmin(true), human.HasPrincipalWith(activePrincipal())}
}

// PlatformAdmin reports whether the tables call for principalID's
// platform administration.
func PlatformAdmin(ctx context.Context, c *ent.Client, principalID uuid.UUID) (bool, error) {
	ok, err := c.Human.Query().
		Where(human.PrincipalID(principalID)).
		Where(HoldingAdmins()...).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("graphstate: reading platform administrator: %w", err)
	}
	return ok, nil
}

// HoldingManagerRelationships returns the predicates of the manager
// relationships that call for access.
func HoldingManagerRelationships() []predicate.ManagerRelationship {
	return []predicate.ManagerRelationship{
		managerrelationship.Active(true),
		managerrelationship.HasManagerWith(activePrincipal()),
	}
}

// Manager reports whether the tables call for managerID managing
// managedID with role.
func Manager(ctx context.Context, c *ent.Client, managedID, managerID uuid.UUID, role string) (bool, error) {
	ok, err := c.ManagerRelationship.Query().
		Where(
			managerrelationship.ManagedPrincipalID(managedID),
			managerrelationship.ManagerPrincipalID(managerID),
			managerrelationship.Role(role),
		).
		Where(HoldingManagerRelationships()...).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("graphstate: reading manager relationship: %w", err)
	}
	return ok, nil
}
