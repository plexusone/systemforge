package organization

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/organization"
)

// RoleCollaborator is the role of a principal granted access to individual
// resources rather than membership of the organization (ADR-008). It is the
// only role a personal organization accepts besides its owner.
const RoleCollaborator = "collaborator"

// ErrInvalidRole is returned for a membership role that is not an
// organization role. The organization roles are owner, admin, member and
// collaborator; editor and viewer were retired (ADR-008), and finer access
// to one resource is a resource role granted through the authorization
// provider.
var ErrInvalidRole = errors.New("invalid organization role")

// ValidRole reports whether role is an organization role.
func ValidRole(role string) bool {
	switch role {
	case RoleOwner, RoleAdmin, RoleMember, RoleCollaborator:
		return true
	}
	return false
}

// ErrPersonalOrganization is returned when an operation would give a
// personal organization a second member or hand it to someone else. A
// personal organization has exactly one member, its owner (ADR-006
// decision 3), and collaborators.
var ErrPersonalOrganization = errors.New("operation not allowed on a personal organization")

// ErrOrganizationDeleted means the organization was deleted (it is
// inactive): it takes no new members, and no membership changes.
var ErrOrganizationDeleted = errors.New("organization has been deleted")

// RequireMembersAllowed returns ErrInvalidRole when role is not an
// organization role, ErrOrganizationDeleted when orgID is a deleted
// (inactive) organization, and ErrPersonalOrganization when orgID is a
// personal organization and role is not RoleCollaborator. It is the check
// every path that creates or changes a membership applies, including the
// invite service and SCIM group membership.
func RequireMembersAllowed(ctx context.Context, client *ent.Client, orgID uuid.UUID, role string) error {
	if !ValidRole(role) {
		return fmt.Errorf("%w: %q (want owner, admin, member or collaborator)", ErrInvalidRole, role)
	}
	org, err := client.Organization.Query().
		Where(organization.IDEQ(orgID)).
		Select(organization.FieldOrgType, organization.FieldActive).
		Only(ctx)
	if ent.IsNotFound(err) {
		// An unknown organization: the caller's own write reports it.
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read organization: %w", err)
	}
	if !org.Active {
		return ErrOrganizationDeleted
	}
	if role == RoleCollaborator {
		return nil
	}
	if org.OrgType == organization.OrgTypePersonal {
		return fmt.Errorf("%w: only its owner and collaborators may belong to it", ErrPersonalOrganization)
	}
	return nil
}

// IsPersonal reports whether the organization exists and is personal.
func IsPersonal(ctx context.Context, client *ent.Client, orgID uuid.UUID) (bool, error) {
	return isPersonal(ctx, client, orgID)
}

// isPersonal reports whether the organization exists and is personal. An
// unknown organization is not personal: the caller's own write reports it.
func isPersonal(ctx context.Context, client *ent.Client, orgID uuid.UUID) (bool, error) {
	t, err := client.Organization.Query().Where(organization.IDEQ(orgID)).Select(organization.FieldOrgType).Strings(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to read organization type: %w", err)
	}
	return len(t) == 1 && t[0] == string(organization.OrgTypePersonal), nil
}
