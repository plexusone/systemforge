package invite

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/resourcegrant"
	"github.com/plexusone/systemforge/internal/apierror"
)

// clientError is an error the client can act on, with the fixed message
// the API answers for it.
type clientError struct {
	err     error
	message string
}

// clientErrors lists the service errors whose fixed message is safe to
// send. A wrapped error's own text is never sent: it may carry database or
// provider details.
var clientErrors = []clientError{
	{ErrPendingInviteExists, "pending invite already exists for this email"},
	{ErrAlreadyMember, "principal is already a member of this organization"},
	{ErrNotPending, "invite is no longer pending"},
	{ErrExpired, "invite has expired"},
	{ErrInviterNotAuthorized, "the inviter may no longer invite to this organization"},
	{ErrAppRoleRequired, "choose an application role for at least one entitled application"},
	{ErrAppRolesNotConfigured, "application roles are not configured"},
	{ErrCollaboratorAppRoles, "collaborators hold no application roles"},
	{ErrResourceInvite, "invalid resource target: give resource type, id and role together, for a collaborator invite"},
	{organization.ErrInvalidRole, "invalid organization role (want owner, admin, member or collaborator)"},
	{organization.ErrOrganizationDeleted, "organization has been deleted"},
	{organization.ErrPersonalOrganization, "operation not allowed on a personal organization"},
	{authz.ErrInvalidResourceRole, "invalid resource role (want viewer, contributor or maintainer)"},
	{authz.ErrInvalidResource, "invalid resource"},
	{authz.ErrResourceOrganizationMismatch, "resource belongs to another organization"},
	{resourcegrant.ErrInactiveMembership, "the principal's membership in the organization is inactive"},
	{approle.ErrUnknownApplication, "unknown application"},
	{approle.ErrUnknownRole, "role not declared by the application"},
	{approle.ErrNotEntitled, "organization is not entitled to the application"},
	{approle.ErrNotMember, "principal is not an active owner, admin or member"},
	{approle.ErrNoSeats, "no seats available for the application"},
	{approle.ErrAlreadyAssigned, "role already assigned"},
}

// serviceError maps an invite service error to an API error: a missing
// invite is 404, a known client error is status with its fixed message,
// and anything else is logged and answered with a generic 500.
func (a *API) serviceError(ctx context.Context, op string, err error, status int) error {
	if errors.Is(err, ErrInviteNotFound) {
		return huma.Error404NotFound("invite not found")
	}
	for _, ce := range clientErrors {
		if errors.Is(err, ce.err) {
			return huma.NewError(status, ce.message)
		}
	}
	return apierror.Internal(ctx, a.config.Logger, "invite: "+op, err)
}

// badRequest is serviceError with a 400 status for client errors.
func (a *API) badRequest(ctx context.Context, op string, err error) error {
	return a.serviceError(ctx, op, err, http.StatusBadRequest)
}
