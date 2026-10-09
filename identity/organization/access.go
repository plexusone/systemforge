package organization

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// callerID returns the authenticated caller, or a 401.
func (a *API) callerID(ctx context.Context) (uuid.UUID, error) {
	resolve := a.config.Caller
	if resolve == nil {
		resolve = requestprincipal.PrincipalUUID
	}
	id, err := resolve(ctx)
	if errors.Is(err, requestprincipal.ErrNoPrincipal) {
		return uuid.Nil, huma.Error401Unauthorized("authentication required")
	}
	if err != nil {
		a.config.Logger.ErrorContext(ctx, "organization: identifying caller", "error", err)
		return uuid.Nil, huma.Error500InternalServerError("identifying caller")
	}
	return id, nil
}

// can reports whether principalID holds action on the organization.
func (a *API) can(ctx context.Context, principalID, orgID uuid.UUID, action authz.Action) (bool, error) {
	ok, err := a.config.Authorizer.Can(ctx, authz.NewUserPrincipal(principalID), action, authz.NewResourceWithID(authz.ResourceTypeOrganization, orgID))
	if err != nil {
		a.config.Logger.ErrorContext(ctx, "organization: authorization check", "action", action, "organization_id", orgID, "error", err)
		return false, huma.Error500InternalServerError("checking authorization")
	}
	return ok, nil
}

// orgFor loads the organization named by slug and returns it with the
// caller after checking action. Callers who may not view the
// organization get 404, so its existence is not confirmed to outsiders.
func (a *API) orgFor(ctx context.Context, slug string, action authz.Action) (*Organization, uuid.UUID, error) {
	if a.config.Authorizer == nil {
		return nil, uuid.Nil, huma.Error501NotImplemented("organization authorization not configured")
	}
	caller, err := a.callerID(ctx)
	if err != nil {
		return nil, uuid.Nil, err
	}
	// An old slug still resolves during its cooling-off period; responses
	// carry the current slug.
	org, _, err := a.service.ResolveSlug(ctx, slug)
	if err != nil {
		return nil, uuid.Nil, huma.Error404NotFound("organization not found")
	}
	ok, err := a.can(ctx, caller, org.ID, action)
	if err != nil {
		return nil, uuid.Nil, err
	}
	if !ok {
		visible, err := a.can(ctx, caller, org.ID, authz.PermOrgView)
		if err != nil {
			return nil, uuid.Nil, err
		}
		if !visible {
			return nil, uuid.Nil, huma.Error404NotFound("organization not found")
		}
		return nil, uuid.Nil, huma.Error403Forbidden("not allowed for this organization")
	}
	return org, caller, nil
}

// requireOwnerRights checks the owner-only permission, which granting,
// changing, or removing the owner role needs.
func (a *API) requireOwnerRights(ctx context.Context, caller, orgID uuid.UUID) error {
	ok, err := a.can(ctx, caller, orgID, authz.PermOrgDelete)
	if err != nil {
		return err
	}
	if !ok {
		return huma.Error403Forbidden("only an owner may grant, change, or remove the owner role")
	}
	return nil
}

// isPlatformAdmin reports whether the caller is a platform administrator,
// when the authorizer can tell.
func (a *API) isPlatformAdmin(ctx context.Context, caller uuid.UUID) (bool, error) {
	pa, ok := a.config.Authorizer.(authz.PlatformAuthorizer)
	if !ok {
		return false, nil
	}
	admin, err := pa.IsPlatformAdmin(ctx, authz.NewUserPrincipal(caller))
	if err != nil {
		a.config.Logger.ErrorContext(ctx, "organization: platform admin check", "error", err)
		return false, huma.Error500InternalServerError("checking authorization")
	}
	return admin, nil
}

// MembershipRoleGetter returns a role getter for rbac.WithRoleGetter
// that reads a principal's role from its active membership in the
// organization. A missing or deactivated membership has no role.
func MembershipRoleGetter(svc Service) func(ctx context.Context, principalID, orgID uuid.UUID) (string, error) {
	return func(ctx context.Context, principalID, orgID uuid.UUID) (string, error) {
		m, err := svc.GetMembership(ctx, orgID, principalID)
		if errors.Is(err, ErrMembershipNotFound) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if !m.Active {
			return "", nil
		}
		return m.Role, nil
	}
}
