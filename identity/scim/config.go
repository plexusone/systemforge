package scim

import (
	"net/url"
	"strings"
)

// Config holds the SCIM server configuration.
type Config struct {
	// BaseURL is the base URL for SCIM resources (e.g., "https://example.com/scim/v2").
	BaseURL string

	// MaxResults is the maximum number of resources returned in a list response.
	MaxResults int

	// DefaultPageSize is the default number of resources per page.
	DefaultPageSize int

	// SupportFiltering indicates whether filtering is supported.
	SupportFiltering bool

	// SupportSorting indicates whether sorting is supported.
	SupportSorting bool

	// SupportPatch indicates whether PATCH operations are supported.
	SupportPatch bool

	// SupportBulk indicates whether bulk operations are supported.
	SupportBulk bool

	// BulkMaxOperations is the maximum number of operations in a bulk request.
	BulkMaxOperations int

	// BulkMaxPayloadSize is the maximum size of a bulk request in bytes.
	BulkMaxPayloadSize int

	// SupportChangePassword indicates whether password changes via SCIM are supported.
	SupportChangePassword bool

	// SupportETag indicates whether ETag-based optimistic locking is supported.
	SupportETag bool

	// AuthenticationSchemes defines the supported authentication methods.
	AuthenticationSchemes []AuthenticationScheme

	// DocumentationURI is an optional URI to SCIM documentation.
	DocumentationURI string
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

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		BaseURL:               "/scim/v2",
		MaxResults:            1000,
		DefaultPageSize:       100,
		SupportFiltering:      true,
		SupportSorting:        true,
		SupportPatch:          true,
		SupportBulk:           true,
		BulkMaxOperations:     1000,
		BulkMaxPayloadSize:    1048576, // 1 MB
		SupportChangePassword: true,
		SupportETag:           true,
		AuthenticationSchemes: []AuthenticationScheme{
			{
				Type:        "oauthbearertoken",
				Name:        "OAuth Bearer Token",
				Description: "Authentication using OAuth 2.0 Bearer Token",
				SpecURI:     "https://www.rfc-editor.org/rfc/rfc6750",
				Primary:     true,
			},
		},
	}
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.BaseURL == "" {
		return ErrInvalidValue("baseURL is required")
	}
	if c.MaxResults <= 0 {
		return ErrInvalidValue("maxResults must be positive")
	}
	if c.DefaultPageSize <= 0 {
		return ErrInvalidValue("defaultPageSize must be positive")
	}
	if c.DefaultPageSize > c.MaxResults {
		return ErrInvalidValue("defaultPageSize cannot exceed maxResults")
	}
	return nil
}

// ResourceLocation returns the full URL for a resource.
func (c *Config) ResourceLocation(resourceType, id string) string {
	base := strings.TrimSuffix(c.BaseURL, "/")
	return base + "/" + resourceType + "s/" + url.PathEscape(id)
}

// UserLocation returns the full URL for a user resource.
func (c *Config) UserLocation(id string) string {
	return c.ResourceLocation("User", id)
}

// GroupLocation returns the full URL for a group resource.
func (c *Config) GroupLocation(id string) string {
	return c.ResourceLocation("Group", id)
}
