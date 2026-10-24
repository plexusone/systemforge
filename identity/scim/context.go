package scim

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type contextKey string

const (
	requestIDKey   contextKey = "scim_request_id"
	authSubjectKey contextKey = "scim_auth_subject"
	authScopesKey  contextKey = "scim_auth_scopes"
	scopeKey       contextKey = "scim_scope"
)

// Scope is what a SCIM credential may provision: one organization (a
// tenant's identity provider) or, for an explicitly marked platform
// operator credential, every organization.
type Scope struct {
	// OrganizationID is the organization a tenant credential provisions.
	OrganizationID uuid.UUID
	// Platform marks a platform operator credential that provisions every
	// organization.
	Platform bool
}

// Valid reports whether the scope names exactly one of an organization or
// the platform.
func (s Scope) Valid() bool {
	return (s.OrganizationID != uuid.Nil) != s.Platform
}

// WithScope binds the request to a provisioning scope. Stores refuse
// requests without a valid scope.
func WithScope(ctx context.Context, scope Scope) context.Context {
	return context.WithValue(ctx, scopeKey, scope)
}

// WithTenant binds the request to one organization.
func WithTenant(ctx context.Context, orgID uuid.UUID) context.Context {
	return WithScope(ctx, Scope{OrganizationID: orgID})
}

// WithPlatformScope binds the request to every organization. Use it only
// for platform operator credentials.
func WithPlatformScope(ctx context.Context) context.Context {
	return WithScope(ctx, Scope{Platform: true})
}

// ScopeFromContext returns the request's provisioning scope.
func ScopeFromContext(ctx context.Context) (Scope, bool) {
	s, ok := ctx.Value(scopeKey).(Scope)
	return s, ok && s.Valid()
}

// WithRequestID adds a request ID to the context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// RequestIDFromContext extracts the request ID from context.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// WithAuthSubject adds the authenticated subject (user/client ID) to the context.
func WithAuthSubject(ctx context.Context, subject string) context.Context {
	return context.WithValue(ctx, authSubjectKey, subject)
}

// AuthSubjectFromContext extracts the authenticated subject from context.
func AuthSubjectFromContext(ctx context.Context) string {
	subject, _ := ctx.Value(authSubjectKey).(string)
	return subject
}

// WithAuthScopes adds the authenticated scopes to the context.
func WithAuthScopes(ctx context.Context, scopes []string) context.Context {
	return context.WithValue(ctx, authScopesKey, scopes)
}

// AuthScopesFromContext extracts the authenticated scopes from context.
func AuthScopesFromContext(ctx context.Context) []string {
	scopes, _ := ctx.Value(authScopesKey).([]string)
	return scopes
}

// HasAuthScope checks if the context has a specific scope.
func HasAuthScope(ctx context.Context, scope string) bool {
	return slices.Contains(AuthScopesFromContext(ctx), scope)
}

// RequestMetadata contains metadata extracted from a SCIM request.
type RequestMetadata struct {
	// Filter is the SCIM filter expression.
	Filter string

	// StartIndex is the 1-based index of the first result (default 1).
	StartIndex int

	// Count is the number of resources to return per page.
	Count int

	// SortBy is the attribute to sort by.
	SortBy string

	// SortOrder is "ascending" or "descending".
	SortOrder string

	// Attributes specifies which attributes to return.
	Attributes []string

	// ExcludedAttributes specifies which attributes to exclude.
	ExcludedAttributes []string

	// IfMatch is the ETag value from If-Match header.
	IfMatch string

	// IfNoneMatch is the ETag value from If-None-Match header.
	IfNoneMatch string
}

// ExtractRequestMetadata extracts SCIM request metadata from an HTTP request.
func ExtractRequestMetadata(r *http.Request) RequestMetadata {
	query := r.URL.Query()

	startIndex := 1
	if s := query.Get("startIndex"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			startIndex = v
		}
	}

	count := 0 // 0 means use default
	if s := query.Get("count"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 0 {
			count = v
		}
	}

	sortOrder := "ascending"
	if s := query.Get("sortOrder"); s != "" {
		if strings.EqualFold(s, "descending") {
			sortOrder = "descending"
		}
	}

	var attributes []string
	if s := query.Get("attributes"); s != "" {
		attributes = splitAndTrim(s, ",")
	}

	var excludedAttributes []string
	if s := query.Get("excludedAttributes"); s != "" {
		excludedAttributes = splitAndTrim(s, ",")
	}

	return RequestMetadata{
		Filter:             query.Get("filter"),
		StartIndex:         startIndex,
		Count:              count,
		SortBy:             query.Get("sortBy"),
		SortOrder:          sortOrder,
		Attributes:         attributes,
		ExcludedAttributes: excludedAttributes,
		IfMatch:            r.Header.Get("If-Match"),
		IfNoneMatch:        r.Header.Get("If-None-Match"),
	}
}

// ToListOptions converts RequestMetadata to ListOptions.
func (m RequestMetadata) ToListOptions(defaultCount int) ListOptions {
	count := m.Count
	if count == 0 {
		count = defaultCount
	}

	return ListOptions{
		Filter:     m.Filter,
		StartIndex: m.StartIndex,
		Count:      count,
		SortBy:     m.SortBy,
		SortOrder:  m.SortOrder,
		Attributes: m.Attributes,
	}
}

// splitAndTrim splits a string by separator and trims whitespace from each part.
func splitAndTrim(s, sep string) []string { //nolint:unparam // sep kept for flexibility
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// GenerateETag generates an ETag value from a version string or timestamp.
func GenerateETag(version string) string {
	return `"` + version + `"`
}

// ParseETag parses an ETag value, removing quotes.
func ParseETag(etag string) string {
	etag = strings.TrimPrefix(etag, "W/")
	etag = strings.Trim(etag, `"`)
	return etag
}

// WriteResponse writes a SCIM response with proper headers.
func WriteResponse(w http.ResponseWriter, status int, etag string, body []byte) {
	w.Header().Set("Content-Type", "application/scim+json")
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	w.WriteHeader(status)
	if body != nil {
		_, _ = w.Write(body)
	}
}
