package organization

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/plexusone/systemforge/internal/apierror"
)

// clientError is an error the client can act on, answered with a fixed
// message: the wrapped error text is never sent, since it may carry
// database details.
type clientError struct {
	err     error
	status  int
	message string
}

// clientErrors lists the service errors answered with their own status and
// fixed message. Any other error is logged and answered with a 500.
var clientErrors = []clientError{
	{ErrInvalidSlug, http.StatusBadRequest, ErrInvalidSlug.Error()},
	{ErrSlugTaken, http.StatusBadRequest, ErrSlugTaken.Error()},
	{ErrSlugReserved, http.StatusBadRequest, ErrSlugReserved.Error()},
	{ErrSlugCoolingOff, http.StatusBadRequest, ErrSlugCoolingOff.Error()},
	{ErrOwnerRequired, http.StatusBadRequest, ErrOwnerRequired.Error()},
	{ErrInvalidRole, http.StatusBadRequest, "invalid organization role (want owner, admin, member or collaborator)"},
	{ErrInvalidOwnerRole, http.StatusBadRequest, ErrInvalidOwnerRole.Error()},
	{ErrNewOwnerNotMember, http.StatusBadRequest, ErrNewOwnerNotMember.Error()},
	{ErrAlreadyMember, http.StatusBadRequest, ErrAlreadyMember.Error()},
	{ErrNotPersonal, http.StatusBadRequest, ErrNotPersonal.Error()},
	{ErrOrganizationDeleted, http.StatusBadRequest, ErrOrganizationDeleted.Error()},
	{ErrPersonalOrganization, http.StatusConflict, ErrPersonalOrganization.Error()},
	{ErrNotOwner, http.StatusForbidden, ErrNotOwner.Error()},
	{ErrOrganizationNotFound, http.StatusNotFound, ErrOrganizationNotFound.Error()},
	{ErrMembershipNotFound, http.StatusNotFound, "member not found"},
}

// serviceError maps a service error to an API error: the errors in
// clientErrors get their fixed message, anything else is logged under op
// and answered with a generic 500.
func (a *API) serviceError(ctx context.Context, op string, err error) error {
	for _, ce := range clientErrors {
		if errors.Is(err, ce.err) {
			return huma.NewError(ce.status, ce.message)
		}
	}
	return apierror.Internal(ctx, a.config.Logger, "organization: "+op, err)
}
