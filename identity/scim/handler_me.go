package scim

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// registerMeEndpoints registers the /Me endpoint.
func (a *API) registerMeEndpoints() {
	baseURL := a.provider.Config().BaseURL

	// Get Me
	huma.Register(a.huma, huma.Operation{
		OperationID:   "getMe",
		Method:        http.MethodGet,
		Path:          baseURL + "/Me",
		Summary:       "Get current user",
		Description:   "Returns the authenticated user's own record (RFC 7644 Section 3.11)",
		Tags:          []string{"Me"},
		DefaultStatus: http.StatusOK,
	}, a.getMe)

	// Patch Me
	huma.Register(a.huma, huma.Operation{
		OperationID:   "patchMe",
		Method:        http.MethodPatch,
		Path:          baseURL + "/Me",
		Summary:       "Patch current user",
		Description:   "Applies partial updates to the authenticated user's record (RFC 7644 Section 3.11)",
		Tags:          []string{"Me"},
		DefaultStatus: http.StatusOK,
	}, a.patchMe)
}

// getMe returns the current authenticated user.
func (a *API) getMe(ctx context.Context, input *struct{}) (*MeOutput, error) {
	service := a.provider.Service()

	user, err := service.GetMe(ctx)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	etag := ""
	if user.Meta != nil {
		etag = GenerateETag(user.Meta.Version)
	}

	return &MeOutput{
		Body: user,
		ETag: etag,
	}, nil
}

// patchMe applies partial updates to the current authenticated user.
func (a *API) patchMe(ctx context.Context, input *MePatchInput) (*MeOutput, error) {
	service := a.provider.Service()

	updated, err := service.PatchMe(ctx, input.Body, input.IfMatch)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	etag := ""
	if updated.Meta != nil {
		etag = GenerateETag(updated.Meta.Version)
	}

	return &MeOutput{
		Body: updated,
		ETag: etag,
	}, nil
}
