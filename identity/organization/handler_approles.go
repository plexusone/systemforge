package organization

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
)

// AppRoleResponse is the API representation of a stored application role.
type AppRoleResponse struct {
	PrincipalID string  `json:"principal_id"`
	Application string  `json:"application"`
	Role        string  `json:"role"`
	AssignedBy  *string `json:"assigned_by,omitempty"`
}

func appRoleToResponse(r *approle.AppRole) *AppRoleResponse {
	resp := &AppRoleResponse{
		PrincipalID: r.PrincipalID.String(),
		Application: r.Application,
		Role:        r.Role,
	}
	if r.AssignedBy != nil {
		s := r.AssignedBy.String()
		resp.AssignedBy = &s
	}
	return resp
}

// ListAppRolesInput is the request for listing an organization's
// application roles.
type ListAppRolesInput struct {
	Slug        string `path:"slug"`
	Application string `query:"application" doc:"Only roles in this application"`
}

// ListAppRolesOutput is the response for listing application roles.
type ListAppRolesOutput struct {
	Body struct {
		AppRoles []*AppRoleResponse `json:"app_roles"`
	}
}

// GetMemberAppRolesInput is the request for a member's application roles.
type GetMemberAppRolesInput struct {
	Slug        string `path:"slug"`
	PrincipalID string `path:"principal_id" format:"uuid"`
}

// GetMemberAppRolesOutput is the response for a member's application
// roles. Effective includes the admin role owners hold implicitly.
type GetMemberAppRolesOutput struct {
	Body struct {
		AppRoles  []*AppRoleResponse `json:"app_roles"`
		Effective map[string]string  `json:"effective"`
	}
}

// SetAppRoleInput is the request for assigning or changing a member's
// role in an application.
type SetAppRoleInput struct {
	Slug        string `path:"slug"`
	PrincipalID string `path:"principal_id" format:"uuid"`
	Application string `path:"application"`
	Body        struct {
		Role string `json:"role" required:"true" minLength:"1"`
	}
}

// SetAppRoleOutput is the response for assigning or changing a role.
type SetAppRoleOutput struct {
	Body *AppRoleResponse
}

// RemoveAppRoleInput is the request for removing a member's role in an
// application.
type RemoveAppRoleInput struct {
	Slug        string `path:"slug"`
	PrincipalID string `path:"principal_id" format:"uuid"`
	Application string `path:"application"`
}

// registerAppRoleEndpoints registers the application role endpoints.
func (a *API) registerAppRoleEndpoints() {
	base := a.config.BasePath + "/organizations/{slug}"
	huma.Register(a.huma, huma.Operation{
		OperationID: "listAppRoles",
		Method:      http.MethodGet,
		Path:        base + "/app-roles",
		Summary:     "List application roles",
		Description: "Returns the application roles assigned in an organization",
		Tags:        []string{"Application roles"},
	}, a.listAppRoles)
	huma.Register(a.huma, huma.Operation{
		OperationID: "getMemberAppRoles",
		Method:      http.MethodGet,
		Path:        base + "/members/{principal_id}/app-roles",
		Summary:     "Get a member's application roles",
		Description: "Returns a member's assigned and effective application roles; a member may read their own",
		Tags:        []string{"Application roles"},
	}, a.getMemberAppRoles)
	huma.Register(a.huma, huma.Operation{
		OperationID: "setAppRole",
		Method:      http.MethodPut,
		Path:        base + "/members/{principal_id}/app-roles/{application}",
		Summary:     "Assign or change an application role",
		Description: "Gives a member a role in an application, or changes the one they have",
		Tags:        []string{"Application roles"},
	}, a.setAppRole)
	huma.Register(a.huma, huma.Operation{
		OperationID:   "removeAppRole",
		Method:        http.MethodDelete,
		Path:          base + "/members/{principal_id}/app-roles/{application}",
		Summary:       "Remove an application role",
		Description:   "Removes a member's role in an application",
		Tags:          []string{"Application roles"},
		DefaultStatus: http.StatusNoContent,
	}, a.removeAppRole)
}

func (a *API) appRoles() (*approle.Service, error) {
	if a.config.AppRoles == nil {
		return nil, huma.Error501NotImplemented("application roles not configured")
	}
	return a.config.AppRoles, nil
}

// appRoleError maps an approle error to an HTTP error.
func (a *API) appRoleError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, approle.ErrAlreadyAssigned),
		errors.Is(err, approle.ErrNoSeats):
		return huma.Error409Conflict(err.Error())
	case errors.Is(err, approle.ErrNotAssigned):
		return huma.Error404NotFound(err.Error())
	case errors.Is(err, approle.ErrUnknownApplication),
		errors.Is(err, approle.ErrUnknownRole),
		errors.Is(err, approle.ErrNotEntitled),
		errors.Is(err, approle.ErrNotMember):
		return huma.Error400BadRequest(err.Error())
	}
	a.config.Logger.ErrorContext(ctx, "organization: application roles", "error", err)
	return huma.Error500InternalServerError("application roles failed")
}

func (a *API) listAppRoles(ctx context.Context, input *ListAppRolesInput) (*ListAppRolesOutput, error) {
	svc, err := a.appRoles()
	if err != nil {
		return nil, err
	}
	org, _, err := a.orgFor(ctx, input.Slug, authz.PermOrgChangeRole)
	if err != nil {
		return nil, err
	}
	roles, err := svc.ListForOrganization(ctx, org.ID, input.Application)
	if err != nil {
		return nil, a.appRoleError(ctx, err)
	}
	out := &ListAppRolesOutput{}
	out.Body.AppRoles = make([]*AppRoleResponse, len(roles))
	for i, r := range roles {
		out.Body.AppRoles[i] = appRoleToResponse(r)
	}
	return out, nil
}

func (a *API) getMemberAppRoles(ctx context.Context, input *GetMemberAppRolesInput) (*GetMemberAppRolesOutput, error) {
	svc, err := a.appRoles()
	if err != nil {
		return nil, err
	}
	principalID, err := uuid.Parse(input.PrincipalID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid principal ID")
	}
	// Members read their own roles; reading anyone else's needs the
	// permission to change roles.
	action := authz.PermOrgChangeRole
	if caller, cerr := a.callerID(ctx); cerr == nil && caller == principalID {
		action = authz.PermOrgView
	}
	org, _, err := a.orgFor(ctx, input.Slug, action)
	if err != nil {
		return nil, err
	}
	roles, err := svc.ListForPrincipal(ctx, org.ID, principalID)
	if err != nil {
		return nil, a.appRoleError(ctx, err)
	}
	effective, err := svc.EffectiveRoles(ctx, principalID, org.ID)
	if err != nil {
		return nil, a.appRoleError(ctx, err)
	}
	out := &GetMemberAppRolesOutput{}
	out.Body.AppRoles = make([]*AppRoleResponse, len(roles))
	for i, r := range roles {
		out.Body.AppRoles[i] = appRoleToResponse(r)
	}
	out.Body.Effective = effective
	return out, nil
}

func (a *API) setAppRole(ctx context.Context, input *SetAppRoleInput) (*SetAppRoleOutput, error) {
	svc, err := a.appRoles()
	if err != nil {
		return nil, err
	}
	principalID, err := uuid.Parse(input.PrincipalID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid principal ID")
	}
	org, caller, err := a.orgFor(ctx, input.Slug, authz.PermOrgChangeRole)
	if err != nil {
		return nil, err
	}
	in := approle.AssignInput{
		OrganizationID: org.ID,
		PrincipalID:    principalID,
		Application:    input.Application,
		Role:           input.Body.Role,
		AssignedBy:     caller,
	}
	role, err := svc.Change(ctx, in)
	if errors.Is(err, approle.ErrNotAssigned) {
		role, err = svc.Assign(ctx, in)
	}
	if err != nil {
		return nil, a.appRoleError(ctx, err)
	}
	return &SetAppRoleOutput{Body: appRoleToResponse(role)}, nil
}

func (a *API) removeAppRole(ctx context.Context, input *RemoveAppRoleInput) (*struct{}, error) {
	svc, err := a.appRoles()
	if err != nil {
		return nil, err
	}
	principalID, err := uuid.Parse(input.PrincipalID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid principal ID")
	}
	org, caller, err := a.orgFor(ctx, input.Slug, authz.PermOrgChangeRole)
	if err != nil {
		return nil, err
	}
	if err := svc.Remove(ctx, org.ID, principalID, input.Application, caller); err != nil {
		return nil, a.appRoleError(ctx, err)
	}
	return nil, nil
}
