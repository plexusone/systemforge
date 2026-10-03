// Package schema provides SCIM schema definitions for discovery endpoints.
package schema

// Schema URIs for SCIM resource types.
const (
	URIUser           = "urn:ietf:params:scim:schemas:core:2.0:User"
	URIGroup          = "urn:ietf:params:scim:schemas:core:2.0:Group"
	URIEnterpriseUser = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	URIListResponse   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	URIPatchOp        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	URIBulkRequest    = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	URIBulkResponse   = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
	URIError          = "urn:ietf:params:scim:api:messages:2.0:Error"
)

// Schema represents a SCIM schema definition as defined in RFC 7643 Section 7.
type Schema struct {
	ID          string      `json:"id"`
	Name        string      `json:"name,omitempty"`
	Description string      `json:"description,omitempty"`
	Attributes  []Attribute `json:"attributes,omitempty"`
	Meta        *SchemaMeta `json:"meta,omitempty"`
}

// SchemaMeta contains schema metadata.
type SchemaMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location,omitempty"`
}

// Attribute represents a SCIM attribute definition.
type Attribute struct {
	Name            string      `json:"name"`
	Type            string      `json:"type"`
	MultiValued     bool        `json:"multiValued"`
	Description     string      `json:"description,omitempty"`
	Required        bool        `json:"required"`
	CaseExact       bool        `json:"caseExact"`
	Mutability      string      `json:"mutability"`
	Returned        string      `json:"returned"`
	Uniqueness      string      `json:"uniqueness"`
	SubAttributes   []Attribute `json:"subAttributes,omitempty"`
	ReferenceTypes  []string    `json:"referenceTypes,omitempty"`
	CanonicalValues []string    `json:"canonicalValues,omitempty"`
}

// Attribute types as defined in RFC 7643 Section 2.3.
const (
	TypeString    = "string"
	TypeBoolean   = "boolean"
	TypeDecimal   = "decimal"
	TypeInteger   = "integer"
	TypeDateTime  = "dateTime"
	TypeBinary    = "binary"
	TypeReference = "reference"
	TypeComplex   = "complex"
)

// Mutability values as defined in RFC 7643 Section 2.2.
const (
	MutabilityReadOnly  = "readOnly"
	MutabilityReadWrite = "readWrite"
	MutabilityImmutable = "immutable"
	MutabilityWriteOnly = "writeOnly"
)

// Returned values as defined in RFC 7643 Section 2.2.
const (
	ReturnedAlways  = "always"
	ReturnedNever   = "never"
	ReturnedDefault = "default"
	ReturnedRequest = "request"
)

// Uniqueness values as defined in RFC 7643 Section 2.2.
const (
	UniquenessNone   = "none"
	UniquenessServer = "server"
	UniquenessGlobal = "global"
)

// ResourceType represents a SCIM resource type definition as defined in RFC 7643 Section 6.
type ResourceType struct {
	ID               string            `json:"id,omitempty"`
	Name             string            `json:"name"`
	Description      string            `json:"description,omitempty"`
	Endpoint         string            `json:"endpoint"`
	Schema           string            `json:"schema"`
	SchemaExtensions []SchemaExtension `json:"schemaExtensions,omitempty"`
	Meta             *ResourceTypeMeta `json:"meta,omitempty"`
}

// SchemaExtension represents a schema extension for a resource type.
type SchemaExtension struct {
	Schema   string `json:"schema"`
	Required bool   `json:"required"`
}

// ResourceTypeMeta contains resource type metadata.
type ResourceTypeMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location,omitempty"`
}

// ServiceProviderConfig represents the SCIM service provider configuration
// as defined in RFC 7643 Section 5.
type ServiceProviderConfig struct {
	Schemas               []string               `json:"schemas"`
	DocumentationURI      string                 `json:"documentationUri,omitempty"`
	Patch                 SupportedFeature       `json:"patch"`
	Bulk                  BulkConfig             `json:"bulk"`
	Filter                FilterConfig           `json:"filter"`
	ChangePassword        SupportedFeature       `json:"changePassword"`
	Sort                  SupportedFeature       `json:"sort"`
	Etag                  SupportedFeature       `json:"etag"`
	AuthenticationSchemes []AuthenticationScheme `json:"authenticationSchemes"`
	Meta                  *SPConfigMeta          `json:"meta,omitempty"`
}

// SupportedFeature indicates whether a feature is supported.
type SupportedFeature struct {
	Supported bool `json:"supported"`
}

// BulkConfig contains bulk operation configuration.
type BulkConfig struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

// FilterConfig contains filter configuration.
type FilterConfig struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// AuthenticationScheme describes a supported authentication method.
type AuthenticationScheme struct {
	Type             string `json:"type"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	SpecURI          string `json:"specUri,omitempty"`
	DocumentationURI string `json:"documentationUri,omitempty"`
	Primary          bool   `json:"primary,omitempty"`
}

// SPConfigMeta contains service provider config metadata.
type SPConfigMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location,omitempty"`
}
