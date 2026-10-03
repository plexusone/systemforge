// Package coreapi provides API management capabilities including rate limiting,
// API key management, and usage tracking.
//
// CoreAPI is designed to work alongside SystemAuth for comprehensive API management:
//   - SystemAuth: Authentication & Authorization (who can access what)
//   - CoreAPI: API Management (how much, how fast, usage tracking)
//
// # Rate Limiting
//
// Rate limiting is policy-based, where policies can be assigned to OAuth clients:
//
//	store := coreapi.NewMemoryPolicyStore()
//	store.SavePolicy(ctx, coreapi.PremiumPolicy)
//	store.AssignPolicyToClient(ctx, "my-oauth-client-id", "premium")
//
// # Integration with HTTP Middleware
//
// Use with SystemForge session/ratelimit for HTTP enforcement:
//
//	resolver := ratelimit.NewPolicyResolver(store)
//	limiter := ratelimit.New(storage, ratelimit.WithResolver(resolver))
//	router.Use(limiter.Middleware())
package coreapi

import (
	"context"
	"time"
)

// RateLimitPolicy defines rate limits that can be applied to API clients.
type RateLimitPolicy struct {
	// ID is the unique identifier for this policy.
	ID string `json:"id"`

	// Name is a human-readable name for the policy.
	Name string `json:"name"`

	// Description explains the policy's purpose.
	Description string `json:"description,omitempty"`

	// Limits defines the rate limits for this policy.
	Limits RateLimits `json:"limits"`

	// EndpointOverrides allows different limits for specific endpoints.
	// Keys are path prefixes (e.g., "/api/v1/uploads").
	EndpointOverrides map[string]RateLimits `json:"endpoint_overrides,omitempty"`

	// Priority determines precedence when multiple policies apply.
	// Higher priority wins. Default is 0.
	Priority int `json:"priority,omitempty"`

	// Enabled controls whether the policy is active.
	Enabled bool `json:"enabled"`

	// Metadata holds arbitrary key-value data.
	Metadata map[string]string `json:"metadata,omitempty"`

	// CreatedAt is when the policy was created.
	CreatedAt time.Time `json:"created_at,omitzero"`

	// UpdatedAt is when the policy was last modified.
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// RateLimits defines rate limits across multiple time windows.
// Zero values mean no limit for that window.
type RateLimits struct {
	// PerSecond is the maximum requests per second.
	PerSecond int `json:"per_second,omitempty"`

	// PerMinute is the maximum requests per minute.
	PerMinute int `json:"per_minute,omitempty"`

	// PerHour is the maximum requests per hour.
	PerHour int `json:"per_hour,omitempty"`

	// PerDay is the maximum requests per day.
	PerDay int `json:"per_day,omitempty"`

	// BurstSize is the maximum burst allowed.
	// If zero, defaults to the most granular rate limit.
	BurstSize int `json:"burst_size,omitempty"`
}

// ClientPolicyBinding associates an OAuth client with a rate limit policy.
type ClientPolicyBinding struct {
	// ClientID is the OAuth 2.0 client_id.
	ClientID string `json:"client_id"`

	// PolicyID is the ID of the bound policy.
	PolicyID string `json:"policy_id"`

	// Enabled controls whether this binding is active.
	Enabled bool `json:"enabled"`

	// CreatedAt is when the binding was created.
	CreatedAt time.Time `json:"created_at,omitzero"`
}

// PolicyStore defines the interface for managing rate limit policies.
type PolicyStore interface {
	// Policy CRUD operations
	GetPolicy(ctx context.Context, policyID string) (*RateLimitPolicy, error)
	ListPolicies(ctx context.Context) ([]*RateLimitPolicy, error)
	CreatePolicy(ctx context.Context, policy *RateLimitPolicy) error
	UpdatePolicy(ctx context.Context, policy *RateLimitPolicy) error
	DeletePolicy(ctx context.Context, policyID string) error

	// Default policy
	GetDefaultPolicy(ctx context.Context) (*RateLimitPolicy, error)
	SetDefaultPolicy(ctx context.Context, policyID string) error

	// Client bindings
	GetPolicyForClient(ctx context.Context, clientID string) (*RateLimitPolicy, error)
	BindClientToPolicy(ctx context.Context, clientID, policyID string) error
	UnbindClient(ctx context.Context, clientID string) error
	ListClientBindings(ctx context.Context) ([]*ClientPolicyBinding, error)
	ListClientsForPolicy(ctx context.Context, policyID string) ([]string, error)
}

// UsageRecord represents API usage for a client in a time period.
type UsageRecord struct {
	// ClientID is the OAuth client that made the requests.
	ClientID string `json:"client_id"`

	// PrincipalID is the user/principal if applicable.
	PrincipalID string `json:"principal_id,omitempty"`

	// Endpoint is the API endpoint (optional, for per-endpoint tracking).
	Endpoint string `json:"endpoint,omitempty"`

	// Period is the time period for this record.
	Period time.Time `json:"period"`

	// PeriodType is the granularity (minute, hour, day).
	PeriodType string `json:"period_type"`

	// RequestCount is the number of requests made.
	RequestCount int64 `json:"request_count"`

	// RateLimitedCount is requests that were rate limited.
	RateLimitedCount int64 `json:"rate_limited_count"`
}

// UsageStore defines the interface for tracking API usage.
type UsageStore interface {
	// RecordRequest increments the usage counter for a client.
	RecordRequest(ctx context.Context, clientID, principalID, endpoint string, rateLimited bool) error

	// GetUsage retrieves usage records for a client.
	GetUsage(ctx context.Context, clientID string, from, to time.Time) ([]*UsageRecord, error)

	// GetUsageSummary retrieves aggregated usage for a client.
	GetUsageSummary(ctx context.Context, clientID string, periodType string, from, to time.Time) (*UsageSummary, error)
}

// UsageSummary provides aggregated usage statistics.
type UsageSummary struct {
	ClientID         string    `json:"client_id"`
	PeriodStart      time.Time `json:"period_start"`
	PeriodEnd        time.Time `json:"period_end"`
	TotalRequests    int64     `json:"total_requests"`
	RateLimitedCount int64     `json:"rate_limited_count"`
	UniqueEndpoints  int       `json:"unique_endpoints"`
	UniquePrincipals int       `json:"unique_principals"`
}
