// Package scim provides SCIM 2.0 (RFC 7643/7644) support for identity provisioning.
package scim

import (
	"time"

	"github.com/plexusone/systemforge/identity/scim/schema"
)

// Schema URIs for SCIM resource types (re-exported from schema package for convenience).
var (
	SchemaUser           = schema.URIUser
	SchemaGroup          = schema.URIGroup
	SchemaEnterpriseUser = schema.URIEnterpriseUser
	SchemaListResponse   = schema.URIListResponse
	SchemaPatchOp        = schema.URIPatchOp
	SchemaBulkRequest    = schema.URIBulkRequest
	SchemaBulkResponse   = schema.URIBulkResponse
	SchemaError          = schema.URIError
)

// Resource types for SCIM endpoints.
const (
	ResourceTypeUser  = "User"
	ResourceTypeGroup = "Group"
)

// Meta contains resource metadata as defined in RFC 7643 Section 3.1.
type Meta struct {
	ResourceType string     `json:"resourceType,omitempty"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
	Version      string     `json:"version,omitempty"`
}

// Resource is the base type for all SCIM resources.
type Resource struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id,omitempty"`
	ExternalID string   `json:"externalId,omitempty"`
	Meta       *Meta    `json:"meta,omitempty"`
}

// MultiValue represents a multi-valued attribute with metadata.
// Used for emails, phone numbers, addresses, etc.
type MultiValue struct {
	Value   string `json:"value,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Name represents a user's name components.
type Name struct {
	Formatted       string `json:"formatted,omitempty"`
	FamilyName      string `json:"familyName,omitempty"`
	GivenName       string `json:"givenName,omitempty"`
	MiddleName      string `json:"middleName,omitempty"`
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

// GroupRef represents a reference to a group in a user's groups attribute.
type GroupRef struct {
	Value   string `json:"value,omitempty"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// MemberRef represents a reference to a member in a group's members attribute.
type MemberRef struct {
	Value   string `json:"value,omitempty"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// User represents a SCIM User resource as defined in RFC 7643 Section 4.1.
type User struct {
	Resource
	UserName          string       `json:"userName"`
	Name              *Name        `json:"name,omitempty"`
	DisplayName       string       `json:"displayName,omitempty"`
	NickName          string       `json:"nickName,omitempty"`
	ProfileURL        string       `json:"profileUrl,omitempty"`
	Title             string       `json:"title,omitempty"`
	UserType          string       `json:"userType,omitempty"`
	PreferredLanguage string       `json:"preferredLanguage,omitempty"`
	Locale            string       `json:"locale,omitempty"`
	Timezone          string       `json:"timezone,omitempty"`
	Active            *bool        `json:"active,omitempty"`
	Password          string       `json:"password,omitempty"` //nolint:gosec // G117: field holds SCIM password attribute, not hardcoded secret
	Emails            []MultiValue `json:"emails,omitempty"`
	PhoneNumbers      []MultiValue `json:"phoneNumbers,omitempty"`
	IMs               []MultiValue `json:"ims,omitempty"`
	Photos            []MultiValue `json:"photos,omitempty"`
	Addresses         []Address    `json:"addresses,omitempty"`
	Groups            []GroupRef   `json:"groups,omitempty"`
	Entitlements      []MultiValue `json:"entitlements,omitempty"`
	Roles             []MultiValue `json:"roles,omitempty"`
	X509Certificates  []MultiValue `json:"x509Certificates,omitempty"`

	// Enterprise User Extension
	EnterpriseUser *EnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
}

// Address represents a physical address.
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"streetAddress,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postalCode,omitempty"`
	Country       string `json:"country,omitempty"`
	Type          string `json:"type,omitempty"`
	Primary       bool   `json:"primary,omitempty"`
}

// EnterpriseUser represents the Enterprise User extension (RFC 7643 Section 4.3).
type EnterpriseUser struct {
	EmployeeNumber string      `json:"employeeNumber,omitempty"`
	CostCenter     string      `json:"costCenter,omitempty"`
	Organization   string      `json:"organization,omitempty"`
	Division       string      `json:"division,omitempty"`
	Department     string      `json:"department,omitempty"`
	Manager        *ManagerRef `json:"manager,omitempty"`
}

// ManagerRef represents a reference to a user's manager.
type ManagerRef struct {
	Value       string `json:"value,omitempty"`
	Ref         string `json:"$ref,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// Group represents a SCIM Group resource as defined in RFC 7643 Section 4.2.
type Group struct {
	Resource
	DisplayName string      `json:"displayName"`
	Members     []MemberRef `json:"members,omitempty"`
}

// ListResponse represents a SCIM list response as defined in RFC 7644 Section 3.4.2.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex,omitempty"`
	ItemsPerPage int      `json:"itemsPerPage,omitempty"`
	Resources    []any    `json:"Resources,omitempty"`
}

// NewListResponse creates a new ListResponse with the proper schema.
func NewListResponse(resources []any, totalResults, startIndex, itemsPerPage int) *ListResponse {
	return &ListResponse{
		Schemas:      []string{SchemaListResponse},
		TotalResults: totalResults,
		StartIndex:   startIndex,
		ItemsPerPage: itemsPerPage,
		Resources:    resources,
	}
}

// ListOptions contains parameters for list operations.
type ListOptions struct {
	Filter     string
	StartIndex int
	Count      int
	SortBy     string
	SortOrder  string
	Attributes []string
}

// DefaultListOptions returns sensible defaults for list operations.
func DefaultListOptions() ListOptions {
	return ListOptions{
		StartIndex: 1,
		Count:      100,
		SortOrder:  "ascending",
	}
}

// PatchRequest represents a SCIM PATCH request as defined in RFC 7644 Section 3.5.2.
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation represents a single PATCH operation.
type PatchOperation struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value,omitempty"`
}

// BulkRequest represents a SCIM bulk request as defined in RFC 7644 Section 3.7.
type BulkRequest struct {
	Schemas      []string        `json:"schemas"`
	FailOnErrors int             `json:"failOnErrors,omitempty"`
	Operations   []BulkOperation `json:"Operations"`
}

// BulkOperation represents a single operation within a bulk request.
type BulkOperation struct {
	Method  string `json:"method"`
	BulkID  string `json:"bulkId,omitempty"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path"`
	Data    any    `json:"data,omitempty"`
}

// BulkResponse represents a SCIM bulk response.
type BulkResponse struct {
	Schemas    []string                `json:"schemas"`
	Operations []BulkResponseOperation `json:"Operations"`
}

// BulkResponseOperation represents a single operation result within a bulk response.
type BulkResponseOperation struct {
	Method   string `json:"method"`
	BulkID   string `json:"bulkId,omitempty"`
	Version  string `json:"version,omitempty"`
	Location string `json:"location,omitempty"`
	Status   string `json:"status"`
	Response any    `json:"response,omitempty"`
}
