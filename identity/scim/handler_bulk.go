package scim

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// registerBulkEndpoints registers the /Bulk endpoint.
func (a *API) registerBulkEndpoints() {
	baseURL := a.provider.Config().BaseURL

	// Bulk Operations
	huma.Register(a.huma, huma.Operation{
		OperationID:   "processBulk",
		Method:        http.MethodPost,
		Path:          baseURL + "/Bulk",
		Summary:       "Process bulk operations",
		Description:   "Processes multiple SCIM operations in a single request (RFC 7644 Section 3.7)",
		Tags:          []string{"Bulk"},
		DefaultStatus: http.StatusOK,
	}, a.processBulk)
}

// processBulk processes multiple SCIM operations in a single request.
func (a *API) processBulk(ctx context.Context, input *BulkInput) (*BulkOutput, error) {
	service := a.provider.Service()

	response, err := service.ProcessBulk(ctx, input.Body)
	if err != nil {
		return nil, toHumaErrorFromErr(ctx, err)
	}

	return &BulkOutput{Body: response}, nil
}
