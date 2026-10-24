//nolint:dupl // Group handlers intentionally mirror User handlers per SCIM RFC 7644
package scim

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// registerGroupEndpoints registers SCIM Group endpoints.
func (a *API) registerGroupEndpoints() {
	baseURL := a.provider.Config().BaseURL

	// List Groups
	huma.Register(a.huma, huma.Operation{
		OperationID:   "listGroups",
		Method:        http.MethodGet,
		Path:          baseURL + "/Groups",
		Summary:       "List groups",
		Description:   "Returns a list of groups with optional filtering and pagination (RFC 7644 Section 3.4.2)",
		Tags:          []string{"Groups"},
		DefaultStatus: http.StatusOK,
	}, a.listGroups)

	// Get Group
	huma.Register(a.huma, huma.Operation{
		OperationID:   "getGroup",
		Method:        http.MethodGet,
		Path:          baseURL + "/Groups/{id}",
		Summary:       "Get a group by ID",
		Description:   "Returns a specific group by ID (RFC 7644 Section 3.4.1)",
		Tags:          []string{"Groups"},
		DefaultStatus: http.StatusOK,
	}, a.getGroup)

	// Create Group
	huma.Register(a.huma, huma.Operation{
		OperationID:   "createGroup",
		Method:        http.MethodPost,
		Path:          baseURL + "/Groups",
		Summary:       "Create a group",
		Description:   "Creates a new group resource (RFC 7644 Section 3.3)",
		Tags:          []string{"Groups"},
		DefaultStatus: http.StatusCreated,
	}, a.createGroup)

	// Replace Group (PUT)
	huma.Register(a.huma, huma.Operation{
		OperationID:   "replaceGroup",
		Method:        http.MethodPut,
		Path:          baseURL + "/Groups/{id}",
		Summary:       "Replace a group",
		Description:   "Replaces an existing group resource (RFC 7644 Section 3.5.1)",
		Tags:          []string{"Groups"},
		DefaultStatus: http.StatusOK,
	}, a.replaceGroup)

	// Patch Group
	huma.Register(a.huma, huma.Operation{
		OperationID:   "patchGroup",
		Method:        http.MethodPatch,
		Path:          baseURL + "/Groups/{id}",
		Summary:       "Patch a group",
		Description:   "Applies partial updates to a group resource (RFC 7644 Section 3.5.2)",
		Tags:          []string{"Groups"},
		DefaultStatus: http.StatusOK,
	}, a.patchGroup)

	// Delete Group
	huma.Register(a.huma, huma.Operation{
		OperationID:   "deleteGroup",
		Method:        http.MethodDelete,
		Path:          baseURL + "/Groups/{id}",
		Summary:       "Delete a group",
		Description:   "Deletes a group resource (RFC 7644 Section 3.6)",
		Tags:          []string{"Groups"},
		DefaultStatus: http.StatusNoContent,
	}, a.deleteGroup)

	// Search Groups (POST)
	huma.Register(a.huma, huma.Operation{
		OperationID:   "searchGroups",
		Method:        http.MethodPost,
		Path:          baseURL + "/Groups/.search",
		Summary:       "Search groups",
		Description:   "Searches for groups using POST with a search request body (RFC 7644 Section 3.4.3)",
		Tags:          []string{"Groups"},
		DefaultStatus: http.StatusOK,
	}, a.searchGroups)
}

// listGroups returns a paginated list of groups.
func (a *API) listGroups(ctx context.Context, input *ListResourcesInput) (*ListGroupsOutput, error) {
	service := a.provider.Service()
	opts := input.ToListOptions(a.provider.Config().DefaultPageSize)
	attrFilter := input.ToAttributeFilter()

	response, err := service.ListGroups(ctx, opts)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	return &ListGroupsOutput{Body: attrFilter.FilterListResponse(response)}, nil
}

// getGroup returns a single group by ID.
func (a *API) getGroup(ctx context.Context, input *GetResourceInput) (*GetGroupOutput, error) {
	service := a.provider.Service()
	attrFilter := input.ToAttributeFilter()

	group, err := service.GetGroup(ctx, input.ID)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	etag := ""
	if group.Meta != nil {
		etag = GenerateETag(group.Meta.Version)
	}

	return &GetGroupOutput{
		Body: attrFilter.FilterGroup(group),
		ETag: etag,
	}, nil
}

// createGroup creates a new group.
func (a *API) createGroup(ctx context.Context, input *CreateGroupInput) (*CreateGroupOutput, error) {
	service := a.provider.Service()

	created, err := service.CreateGroup(ctx, input.Body)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	etag := ""
	if created.Meta != nil {
		etag = GenerateETag(created.Meta.Version)
	}

	return &CreateGroupOutput{
		Body:     created,
		Location: a.provider.Config().GroupLocation(created.ID),
		ETag:     etag,
	}, nil
}

// replaceGroup replaces an existing group (PUT semantics).
func (a *API) replaceGroup(ctx context.Context, input *UpdateGroupInput) (*UpdateGroupOutput, error) {
	service := a.provider.Service()

	updated, err := service.UpdateGroup(ctx, input.ID, input.Body, input.IfMatch)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	etag := ""
	if updated.Meta != nil {
		etag = GenerateETag(updated.Meta.Version)
	}

	return &UpdateGroupOutput{
		Body: updated,
		ETag: etag,
	}, nil
}

// patchGroup applies partial updates to a group.
func (a *API) patchGroup(ctx context.Context, input *PatchResourceInput) (*UpdateGroupOutput, error) {
	service := a.provider.Service()

	updated, err := service.PatchGroup(ctx, input.ID, input.Body, input.IfMatch)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	etag := ""
	if updated.Meta != nil {
		etag = GenerateETag(updated.Meta.Version)
	}

	return &UpdateGroupOutput{
		Body: updated,
		ETag: etag,
	}, nil
}

// deleteGroup deletes a group.
func (a *API) deleteGroup(ctx context.Context, input *DeleteResourceInput) (*struct{}, error) {
	service := a.provider.Service()

	if err := service.DeleteGroup(ctx, input.ID); err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	return nil, nil
}

// searchGroups searches for groups using POST.
func (a *API) searchGroups(ctx context.Context, input *SearchInput) (*SearchOutput, error) {
	service := a.provider.Service()
	opts := input.Body.ToListOptions(a.provider.Config().DefaultPageSize)
	attrFilter := NewAttributeFilter(input.Body.Attributes, input.Body.ExcludedAttributes)

	response, err := service.ListGroups(ctx, opts)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	return &SearchOutput{Body: attrFilter.FilterListResponse(response)}, nil
}
