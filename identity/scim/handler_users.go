//nolint:dupl // User handlers intentionally mirror Group handlers per SCIM RFC 7644
package scim

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// registerUserEndpoints registers SCIM User endpoints.
func (a *API) registerUserEndpoints() {
	baseURL := a.provider.Config().BaseURL

	// List Users
	huma.Register(a.huma, huma.Operation{
		OperationID:   "listUsers",
		Method:        http.MethodGet,
		Path:          baseURL + "/Users",
		Summary:       "List users",
		Description:   "Returns a list of users with optional filtering and pagination (RFC 7644 Section 3.4.2)",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusOK,
	}, a.listUsers)

	// Get User
	huma.Register(a.huma, huma.Operation{
		OperationID:   "getUser",
		Method:        http.MethodGet,
		Path:          baseURL + "/Users/{id}",
		Summary:       "Get a user by ID",
		Description:   "Returns a specific user by ID (RFC 7644 Section 3.4.1)",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusOK,
	}, a.getUser)

	// Create User
	huma.Register(a.huma, huma.Operation{
		OperationID:   "createUser",
		Method:        http.MethodPost,
		Path:          baseURL + "/Users",
		Summary:       "Create a user",
		Description:   "Creates a new user resource (RFC 7644 Section 3.3)",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusCreated,
	}, a.createUser)

	// Replace User (PUT)
	huma.Register(a.huma, huma.Operation{
		OperationID:   "replaceUser",
		Method:        http.MethodPut,
		Path:          baseURL + "/Users/{id}",
		Summary:       "Replace a user",
		Description:   "Replaces an existing user resource (RFC 7644 Section 3.5.1)",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusOK,
	}, a.replaceUser)

	// Patch User
	huma.Register(a.huma, huma.Operation{
		OperationID:   "patchUser",
		Method:        http.MethodPatch,
		Path:          baseURL + "/Users/{id}",
		Summary:       "Patch a user",
		Description:   "Applies partial updates to a user resource (RFC 7644 Section 3.5.2)",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusOK,
	}, a.patchUser)

	// Delete User
	huma.Register(a.huma, huma.Operation{
		OperationID:   "deleteUser",
		Method:        http.MethodDelete,
		Path:          baseURL + "/Users/{id}",
		Summary:       "Delete a user",
		Description:   "Deletes a user resource (RFC 7644 Section 3.6)",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusNoContent,
	}, a.deleteUser)

	// Search Users (POST)
	huma.Register(a.huma, huma.Operation{
		OperationID:   "searchUsers",
		Method:        http.MethodPost,
		Path:          baseURL + "/Users/.search",
		Summary:       "Search users",
		Description:   "Searches for users using POST with a search request body (RFC 7644 Section 3.4.3)",
		Tags:          []string{"Users"},
		DefaultStatus: http.StatusOK,
	}, a.searchUsers)
}

// listUsers returns a paginated list of users.
func (a *API) listUsers(ctx context.Context, input *ListResourcesInput) (*ListUsersOutput, error) {
	service := a.provider.Service()
	opts := input.ToListOptions(a.provider.Config().DefaultPageSize)
	attrFilter := input.ToAttributeFilter()

	response, err := service.ListUsers(ctx, opts)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	return &ListUsersOutput{Body: attrFilter.FilterListResponse(response)}, nil
}

// getUser returns a single user by ID.
func (a *API) getUser(ctx context.Context, input *GetResourceInput) (*GetUserOutput, error) {
	service := a.provider.Service()
	attrFilter := input.ToAttributeFilter()

	user, err := service.GetUser(ctx, input.ID)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	etag := ""
	if user.Meta != nil {
		etag = GenerateETag(user.Meta.Version)
	}

	return &GetUserOutput{
		Body: attrFilter.FilterUser(user),
		ETag: etag,
	}, nil
}

// createUser creates a new user.
func (a *API) createUser(ctx context.Context, input *CreateUserInput) (*CreateUserOutput, error) {
	service := a.provider.Service()

	created, err := service.CreateUser(ctx, input.Body)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	etag := ""
	if created.Meta != nil {
		etag = GenerateETag(created.Meta.Version)
	}

	return &CreateUserOutput{
		Body:     created,
		Location: a.provider.Config().UserLocation(created.ID),
		ETag:     etag,
	}, nil
}

// replaceUser replaces an existing user (PUT semantics).
func (a *API) replaceUser(ctx context.Context, input *UpdateUserInput) (*UpdateUserOutput, error) {
	service := a.provider.Service()

	updated, err := service.UpdateUser(ctx, input.ID, input.Body, input.IfMatch)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	etag := ""
	if updated.Meta != nil {
		etag = GenerateETag(updated.Meta.Version)
	}

	return &UpdateUserOutput{
		Body: updated,
		ETag: etag,
	}, nil
}

// patchUser applies partial updates to a user.
func (a *API) patchUser(ctx context.Context, input *PatchResourceInput) (*UpdateUserOutput, error) {
	service := a.provider.Service()

	updated, err := service.PatchUser(ctx, input.ID, input.Body, input.IfMatch)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	etag := ""
	if updated.Meta != nil {
		etag = GenerateETag(updated.Meta.Version)
	}

	return &UpdateUserOutput{
		Body: updated,
		ETag: etag,
	}, nil
}

// deleteUser deletes a user.
func (a *API) deleteUser(ctx context.Context, input *DeleteResourceInput) (*struct{}, error) {
	service := a.provider.Service()

	if err := service.DeleteUser(ctx, input.ID); err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	return nil, nil
}

// searchUsers searches for users using POST.
func (a *API) searchUsers(ctx context.Context, input *SearchInput) (*SearchOutput, error) {
	service := a.provider.Service()
	opts := input.Body.ToListOptions(a.provider.Config().DefaultPageSize)
	attrFilter := NewAttributeFilter(input.Body.Attributes, input.Body.ExcludedAttributes)

	response, err := service.ListUsers(ctx, opts)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	return &SearchOutput{Body: attrFilter.FilterListResponse(response)}, nil
}
