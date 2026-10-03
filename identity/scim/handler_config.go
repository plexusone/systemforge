package scim

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// registerConfigEndpoints registers SCIM discovery endpoints.
func (a *API) registerConfigEndpoints() {
	baseURL := a.provider.Config().BaseURL

	// ServiceProviderConfig
	huma.Register(a.huma, huma.Operation{
		OperationID:   "getServiceProviderConfig",
		Method:        http.MethodGet,
		Path:          baseURL + "/ServiceProviderConfig",
		Summary:       "Get service provider configuration",
		Description:   "Returns the SCIM service provider configuration (RFC 7643 Section 5)",
		Tags:          []string{"Discovery"},
		DefaultStatus: http.StatusOK,
	}, a.getServiceProviderConfig)

	// List Schemas
	huma.Register(a.huma, huma.Operation{
		OperationID:   "listSchemas",
		Method:        http.MethodGet,
		Path:          baseURL + "/Schemas",
		Summary:       "List all schemas",
		Description:   "Returns all supported SCIM schemas (RFC 7643 Section 7)",
		Tags:          []string{"Discovery"},
		DefaultStatus: http.StatusOK,
	}, a.listSchemas)

	// Get Schema by ID
	huma.Register(a.huma, huma.Operation{
		OperationID:   "getSchema",
		Method:        http.MethodGet,
		Path:          baseURL + "/Schemas/{id}",
		Summary:       "Get a schema by ID",
		Description:   "Returns a specific SCIM schema by its URN",
		Tags:          []string{"Discovery"},
		DefaultStatus: http.StatusOK,
	}, a.getSchema)

	// List ResourceTypes
	huma.Register(a.huma, huma.Operation{
		OperationID:   "listResourceTypes",
		Method:        http.MethodGet,
		Path:          baseURL + "/ResourceTypes",
		Summary:       "List all resource types",
		Description:   "Returns all supported SCIM resource types (RFC 7643 Section 6)",
		Tags:          []string{"Discovery"},
		DefaultStatus: http.StatusOK,
	}, a.listResourceTypes)

	// Get ResourceType by name
	huma.Register(a.huma, huma.Operation{
		OperationID:   "getResourceType",
		Method:        http.MethodGet,
		Path:          baseURL + "/ResourceTypes/{name}",
		Summary:       "Get a resource type by name",
		Description:   "Returns a specific SCIM resource type by name",
		Tags:          []string{"Discovery"},
		DefaultStatus: http.StatusOK,
	}, a.getResourceType)
}

// getServiceProviderConfig returns the SCIM service provider configuration.
func (a *API) getServiceProviderConfig(ctx context.Context, input *struct{}) (*ServiceProviderConfigOutput, error) {
	config := a.provider.ServiceProviderConfig()
	return &ServiceProviderConfigOutput{Body: config}, nil
}

// listSchemas returns all supported SCIM schemas.
func (a *API) listSchemas(ctx context.Context, input *struct{}) (*ListSchemasOutput, error) {
	schemas := a.provider.Schemas()
	resources := make([]any, len(schemas))
	for i, s := range schemas {
		resources[i] = s
	}
	response := NewListResponse(resources, len(schemas), 1, len(schemas))
	return &ListSchemasOutput{Body: response}, nil
}

// getSchema returns a specific schema by ID.
func (a *API) getSchema(ctx context.Context, input *SchemaIDInput) (*GetSchemaOutput, error) {
	schemas := a.provider.Schemas()
	for _, s := range schemas {
		if s.ID == input.ID {
			return &GetSchemaOutput{Body: &s}, nil
		}
	}
	return nil, toHumaError(ErrNotFound("schema not found: " + input.ID))
}

// listResourceTypes returns all supported resource types.
func (a *API) listResourceTypes(ctx context.Context, input *struct{}) (*ListResourceTypesOutput, error) {
	resourceTypes := a.provider.ResourceTypes()
	resources := make([]any, len(resourceTypes))
	for i, rt := range resourceTypes {
		resources[i] = rt
	}
	response := NewListResponse(resources, len(resourceTypes), 1, len(resourceTypes))
	return &ListResourceTypesOutput{Body: response}, nil
}

// getResourceType returns a specific resource type by name.
func (a *API) getResourceType(ctx context.Context, input *ResourceTypeNameInput) (*GetResourceTypeOutput, error) {
	resourceTypes := a.provider.ResourceTypes()
	for _, rt := range resourceTypes {
		if rt.Name == input.Name {
			return &GetResourceTypeOutput{Body: &rt}, nil
		}
	}
	return nil, toHumaError(ErrNotFound("resource type not found: " + input.Name))
}

// toHumaError converts a SCIM error to a Huma error.
func toHumaError(err *Error) error {
	// Use appropriate Huma error constructor based on status
	switch err.Status {
	case http.StatusBadRequest:
		return huma.Error400BadRequest(err.Detail)
	case http.StatusUnauthorized:
		return huma.Error401Unauthorized(err.Detail)
	case http.StatusForbidden:
		return huma.Error403Forbidden(err.Detail)
	case http.StatusNotFound:
		return huma.Error404NotFound(err.Detail)
	case http.StatusConflict:
		return huma.Error409Conflict(err.Detail)
	case http.StatusPreconditionFailed:
		return huma.NewError(http.StatusPreconditionFailed, err.Detail)
	case http.StatusInternalServerError:
		return huma.Error500InternalServerError(err.Detail)
	case http.StatusNotImplemented:
		return huma.Error501NotImplemented(err.Detail)
	default:
		return huma.NewError(err.Status, err.Detail)
	}
}

// toHumaErrorFromErr converts a standard error to a Huma error.
// If the error is a SCIM error, it preserves the status code.
func toHumaErrorFromErr(err error) error {
	if scimErr, ok := err.(*Error); ok {
		return toHumaError(scimErr)
	}
	return huma.Error500InternalServerError(err.Error())
}
