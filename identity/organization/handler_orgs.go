package organization

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

// Organization API request/response types

// OrgResponse is the API representation of an organization.
type OrgResponse struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Slug             string         `json:"slug"`
	OrgType          string         `json:"org_type"`
	OwnerPrincipalID *string        `json:"owner_principal_id,omitempty"`
	LogoURL          *string        `json:"logo_url,omitempty"`
	Description      *string        `json:"description,omitempty"`
	WebsiteURL       *string        `json:"website_url,omitempty"`
	Plan             string         `json:"plan"`
	Active           bool           `json:"active"`
	Settings         map[string]any `json:"settings,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

func orgToResponse(org *Organization) *OrgResponse {
	resp := &OrgResponse{
		ID:          org.ID.String(),
		Name:        org.Name,
		Slug:        org.Slug,
		OrgType:     string(org.OrgType),
		LogoURL:     org.LogoURL,
		Description: org.Description,
		WebsiteURL:  org.WebsiteURL,
		Plan:        string(org.Plan),
		Active:      org.Active,
		Settings:    org.Settings,
		CreatedAt:   org.CreatedAt,
		UpdatedAt:   org.UpdatedAt,
	}
	if org.OwnerPrincipalID != nil {
		s := org.OwnerPrincipalID.String()
		resp.OwnerPrincipalID = &s
	}
	return resp
}

// CreateOrgInput is the request body for creating an organization.
type CreateOrgInput struct {
	Body struct {
		Name        string         `json:"name" required:"true" minLength:"1" maxLength:"100"`
		Slug        string         `json:"slug" required:"true" minLength:"3" maxLength:"63" pattern:"^[a-z][a-z0-9-]*[a-z0-9]$"`
		OrgType     string         `json:"org_type,omitempty" enum:"personal,team,enterprise" default:"team"`
		LogoURL     *string        `json:"logo_url,omitempty"`
		Description *string        `json:"description,omitempty"`
		WebsiteURL  *string        `json:"website_url,omitempty"`
		Plan        string         `json:"plan,omitempty" enum:"free,starter,pro,enterprise" default:"free"`
		Settings    map[string]any `json:"settings,omitempty"`
	}
}

// CreateOrgOutput is the response for creating an organization.
type CreateOrgOutput struct {
	Body *OrgResponse
}

// GetOrgInput is the request for getting an organization.
type GetOrgInput struct {
	Slug string `path:"slug"`
}

// GetOrgOutput is the response for getting an organization.
type GetOrgOutput struct {
	Body *OrgResponse
}

// UpdateOrgInput is the request for updating an organization.
type UpdateOrgInput struct {
	Slug string `path:"slug"`
	Body struct {
		Name        *string        `json:"name,omitempty" maxLength:"100"`
		LogoURL     *string        `json:"logo_url,omitempty"`
		Description *string        `json:"description,omitempty"`
		WebsiteURL  *string        `json:"website_url,omitempty"`
		Plan        *string        `json:"plan,omitempty" enum:"free,starter,pro,enterprise"`
		Settings    map[string]any `json:"settings,omitempty"`
	}
}

// UpdateOrgOutput is the response for updating an organization.
type UpdateOrgOutput struct {
	Body *OrgResponse
}

// DeleteOrgInput is the request for deleting an organization.
type DeleteOrgInput struct {
	Slug string `path:"slug"`
}

// ListOrgsInput is the request for listing organizations.
type ListOrgsInput struct {
	OrgType *string `query:"org_type" enum:"personal,team,enterprise"`
	Plan    *string `query:"plan" enum:"free,starter,pro,enterprise"`
	Active  *bool   `query:"active"`
	Limit   int     `query:"limit" default:"20" minimum:"1" maximum:"100"`
	Offset  int     `query:"offset" default:"0" minimum:"0"`
}

// ListOrgsOutput is the response for listing organizations.
type ListOrgsOutput struct {
	Body struct {
		Organizations []*OrgResponse `json:"organizations"`
		Total         int            `json:"total"`
	}
}

// CheckSlugInput is the request for checking slug availability.
type CheckSlugInput struct {
	Slug string `path:"slug"`
}

// CheckSlugOutput is the response for checking slug availability.
type CheckSlugOutput struct {
	Body struct {
		Available bool   `json:"available"`
		Slug      string `json:"slug"`
	}
}

// registerOrgEndpoints registers organization CRUD endpoints.
//
//nolint:dupl // Huma endpoint registration boilerplate - similar structure, different endpoints
func (a *API) registerOrgEndpoints() {
	basePath := a.config.BasePath

	// Create Organization
	huma.Register(a.huma, huma.Operation{
		OperationID:   "createOrganization",
		Method:        http.MethodPost,
		Path:          basePath + "/organizations",
		Summary:       "Create an organization",
		Description:   "Creates a new organization",
		Tags:          []string{"Organizations"},
		DefaultStatus: http.StatusCreated,
	}, a.createOrg)

	// Get Organization
	huma.Register(a.huma, huma.Operation{
		OperationID:   "getOrganization",
		Method:        http.MethodGet,
		Path:          basePath + "/organizations/{slug}",
		Summary:       "Get an organization",
		Description:   "Returns an organization by slug",
		Tags:          []string{"Organizations"},
		DefaultStatus: http.StatusOK,
	}, a.getOrg)

	// Update Organization
	huma.Register(a.huma, huma.Operation{
		OperationID:   "updateOrganization",
		Method:        http.MethodPatch,
		Path:          basePath + "/organizations/{slug}",
		Summary:       "Update an organization",
		Description:   "Updates an existing organization",
		Tags:          []string{"Organizations"},
		DefaultStatus: http.StatusOK,
	}, a.updateOrg)

	// Delete Organization
	huma.Register(a.huma, huma.Operation{
		OperationID:   "deleteOrganization",
		Method:        http.MethodDelete,
		Path:          basePath + "/organizations/{slug}",
		Summary:       "Delete an organization",
		Description:   "Soft-deletes an organization",
		Tags:          []string{"Organizations"},
		DefaultStatus: http.StatusNoContent,
	}, a.deleteOrg)

	// List Organizations
	huma.Register(a.huma, huma.Operation{
		OperationID:   "listOrganizations",
		Method:        http.MethodGet,
		Path:          basePath + "/organizations",
		Summary:       "List organizations",
		Description:   "Returns a list of organizations with optional filtering",
		Tags:          []string{"Organizations"},
		DefaultStatus: http.StatusOK,
	}, a.listOrgs)

	// Check Slug Availability
	huma.Register(a.huma, huma.Operation{
		OperationID:   "checkSlugAvailability",
		Method:        http.MethodGet,
		Path:          basePath + "/organizations/check-slug/{slug}",
		Summary:       "Check slug availability",
		Description:   "Checks if an organization slug is available",
		Tags:          []string{"Organizations"},
		DefaultStatus: http.StatusOK,
	}, a.checkSlug)
}

func (a *API) createOrg(ctx context.Context, input *CreateOrgInput) (*CreateOrgOutput, error) {
	orgType := OrgTypeTeam
	if input.Body.OrgType != "" {
		orgType = OrgType(input.Body.OrgType)
	}

	plan := PlanFree
	if input.Body.Plan != "" {
		plan = Plan(input.Body.Plan)
	}

	org, err := a.service.Create(ctx, CreateOrganizationInput{
		Name:        input.Body.Name,
		Slug:        input.Body.Slug,
		OrgType:     orgType,
		LogoURL:     input.Body.LogoURL,
		Description: input.Body.Description,
		WebsiteURL:  input.Body.WebsiteURL,
		Plan:        plan,
		Settings:    input.Body.Settings,
	})
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	return &CreateOrgOutput{Body: orgToResponse(org)}, nil
}

func (a *API) getOrg(ctx context.Context, input *GetOrgInput) (*GetOrgOutput, error) {
	org, err := a.service.GetBySlug(ctx, input.Slug)
	if err != nil {
		return nil, huma.Error404NotFound(err.Error())
	}

	return &GetOrgOutput{Body: orgToResponse(org)}, nil
}

func (a *API) updateOrg(ctx context.Context, input *UpdateOrgInput) (*UpdateOrgOutput, error) {
	org, err := a.service.GetBySlug(ctx, input.Slug)
	if err != nil {
		return nil, huma.Error404NotFound(err.Error())
	}

	var plan *Plan
	if input.Body.Plan != nil {
		p := Plan(*input.Body.Plan)
		plan = &p
	}

	updated, err := a.service.Update(ctx, org.ID, UpdateOrganizationInput{
		Name:        input.Body.Name,
		LogoURL:     input.Body.LogoURL,
		Description: input.Body.Description,
		WebsiteURL:  input.Body.WebsiteURL,
		Plan:        plan,
		Settings:    input.Body.Settings,
	})
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	return &UpdateOrgOutput{Body: orgToResponse(updated)}, nil
}

func (a *API) deleteOrg(ctx context.Context, input *DeleteOrgInput) (*struct{}, error) {
	org, err := a.service.GetBySlug(ctx, input.Slug)
	if err != nil {
		return nil, huma.Error404NotFound(err.Error())
	}

	if err := a.service.Delete(ctx, org.ID); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	return nil, nil
}

func (a *API) listOrgs(ctx context.Context, input *ListOrgsInput) (*ListOrgsOutput, error) {
	var orgType *OrgType
	if input.OrgType != nil {
		t := OrgType(*input.OrgType)
		orgType = &t
	}

	var plan *Plan
	if input.Plan != nil {
		p := Plan(*input.Plan)
		plan = &p
	}

	orgs, err := a.service.List(ctx, ListOrganizationsInput{
		OrgType: orgType,
		Plan:    plan,
		Active:  input.Active,
		Limit:   input.Limit,
		Offset:  input.Offset,
	})
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}

	responses := make([]*OrgResponse, len(orgs))
	for i, org := range orgs {
		responses[i] = orgToResponse(org)
	}

	output := &ListOrgsOutput{}
	output.Body.Organizations = responses
	output.Body.Total = len(responses)

	return output, nil
}

func (a *API) checkSlug(ctx context.Context, input *CheckSlugInput) (*CheckSlugOutput, error) {
	available, err := a.service.SlugAvailable(ctx, input.Slug)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}

	output := &CheckSlugOutput{}
	output.Body.Available = available
	output.Body.Slug = input.Slug

	return output, nil
}
