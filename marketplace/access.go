package marketplace

import (
	"context"
	"errors"
	"log/slog"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/internal/apierror"
)

// WithAuthorizer sets the authorizer the API checks organization
// permissions with (authz.PermOrgView, PermOrgEdit, PermOrgManage on the
// listing's creator organization or the license's organization). Until
// one is configured, every organization-scoped operation is refused; only
// published listings can be read.
func WithAuthorizer(a authz.Authorizer) APIOption {
	return func(api *API) { api.authz = a }
}

// callerID returns the authenticated caller, or a 401.
func (a *API) callerID(ctx context.Context) (uuid.UUID, error) {
	id, err := a.caller(ctx)
	if errors.Is(err, ErrNoCaller) {
		return uuid.Nil, huma.Error401Unauthorized("authentication required")
	}
	if err != nil {
		slog.ErrorContext(ctx, "marketplace: identifying caller", "error", err)
		return uuid.Nil, huma.Error500InternalServerError("identifying caller")
	}
	return id, nil
}

// requireOrg returns the authenticated caller after checking that it holds
// action on the organization.
func (a *API) requireOrg(ctx context.Context, orgID uuid.UUID, action authz.Action) (uuid.UUID, error) {
	if a.authz == nil {
		return uuid.Nil, huma.Error501NotImplemented("marketplace authorization not configured")
	}
	caller, err := a.callerID(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	ok, err := a.canOrg(ctx, caller, orgID, action)
	if err != nil {
		return uuid.Nil, err
	}
	if !ok {
		return uuid.Nil, huma.Error403Forbidden("not allowed for this organization")
	}
	return caller, nil
}

// canOrg reports whether principalID holds action on the organization.
func (a *API) canOrg(ctx context.Context, principalID, orgID uuid.UUID, action authz.Action) (bool, error) {
	ok, err := a.authz.Can(ctx, authz.NewUserPrincipal(principalID), action, authz.NewResourceWithID(authz.ResourceTypeOrganization, orgID))
	if err != nil {
		slog.ErrorContext(ctx, "marketplace: authorization check", "action", action, "organization_id", orgID, "error", err)
		return false, huma.Error500InternalServerError("checking authorization")
	}
	return ok, nil
}

// canViewOrg reports whether the request's caller may view the
// organization, without failing when the caller is anonymous or no
// authorizer is configured.
func (a *API) canViewOrg(ctx context.Context, orgID uuid.UUID) (bool, error) {
	if a.authz == nil {
		return false, nil
	}
	caller, err := a.caller(ctx)
	if errors.Is(err, ErrNoCaller) {
		return false, nil
	}
	if err != nil {
		slog.ErrorContext(ctx, "marketplace: identifying caller", "error", err)
		return false, huma.Error500InternalServerError("identifying caller")
	}
	return a.canOrg(ctx, caller, orgID, authz.PermOrgView)
}

// listingFor loads a listing and checks action on its creator organization.
func (a *API) listingFor(ctx context.Context, rawID string, action authz.Action) (*Listing, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid listing ID")
	}
	listing, err := a.listings.Get(ctx, id)
	if errors.Is(err, ErrListingNotFound) {
		return nil, huma.Error404NotFound("listing not found")
	}
	if err != nil {
		return nil, apierror.Internal(ctx, nil, "marketplace: loading listing", err)
	}
	if _, err := a.requireOrg(ctx, listing.CreatorOrgID, action); err != nil {
		return nil, err
	}
	return listing, nil
}

// licenseFor loads a license and checks action on its organization. A
// caller who may not view the license gets 404, so license IDs are not
// confirmed to outsiders.
func (a *API) licenseFor(ctx context.Context, rawID string, action authz.Action) (*License, uuid.UUID, error) {
	id, err := uuid.Parse(rawID)
	if err != nil {
		return nil, uuid.Nil, huma.Error400BadRequest("invalid license ID")
	}
	license, err := a.licenses.Get(ctx, id)
	if errors.Is(err, ErrLicenseNotFound) {
		return nil, uuid.Nil, huma.Error404NotFound("license not found")
	}
	if err != nil {
		return nil, uuid.Nil, apierror.Internal(ctx, nil, "marketplace: loading license", err)
	}
	caller, err := a.requireOrg(ctx, license.OrganizationID, action)
	if err != nil {
		var se huma.StatusError
		if errors.As(err, &se) && se.GetStatus() == 403 && action == authz.PermOrgView {
			return nil, uuid.Nil, huma.Error404NotFound("license not found")
		}
		return nil, uuid.Nil, err
	}
	return license, caller, nil
}
