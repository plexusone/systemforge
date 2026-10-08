package bff

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

// HumaConfig contains configuration for Huma BFF registration.
type HumaConfig struct {
	// Handler is the BFF handler to use for operations.
	Handler *Handler

	// PathPrefix is the prefix for all BFF routes.
	// Default: "/bff".
	PathPrefix string

	// Tags are OpenAPI tags for BFF endpoints.
	// Default: ["BFF"].
	Tags []string

	// IncludeRateLimitDocs adds x-ratelimit-* extensions to OpenAPI.
	// Default: true.
	IncludeRateLimitDocs bool
}

// RegisterHumaRoutes registers BFF endpoints with a Huma API for OpenAPI generation.
// The actual request handling is done by chi-based handlers in Handler.Router().
//
// Usage:
//
//	// Create BFF handler
//	bffHandler, _ := bff.NewHandler(config)
//
//	// Mount chi routes for actual handling
//	router.Mount("/bff", bffHandler.Router())
//
//	// Register with Huma for OpenAPI spec
//	bff.RegisterHumaRoutes(humaAPI, bff.HumaConfig{
//	    Handler:    bffHandler,
//	    PathPrefix: "/bff",
//	})
func RegisterHumaRoutes(api huma.API, config HumaConfig) {
	if config.PathPrefix == "" {
		config.PathPrefix = "/bff"
	}
	if len(config.Tags) == 0 {
		config.Tags = []string{"BFF"}
	}

	// GET /bff/session - Check session status
	huma.Register(api, huma.Operation{
		OperationID: "bff-get-session",
		Method:      http.MethodGet,
		Path:        config.PathPrefix + "/session",
		Summary:     "Get session status",
		Description: "Returns the current session status. Uses HTTP-only session cookie for authentication. This endpoint does not require the Origin header.",
		Tags:        config.Tags,
		Extensions: map[string]any{
			"x-internal":    true,
			"x-cookie-auth": true,
		},
	}, func(ctx context.Context, input *GetSessionInput) (*GetSessionOutput, error) {
		// This is a stub - actual handling is done by chi handler
		return &GetSessionOutput{
			Body: SessionStatusResponse{Authenticated: false},
		}, nil
	})

	// POST /bff/logout - Logout and clear session
	logoutExt := map[string]any{
		"x-internal":       true,
		"x-cookie-auth":    true,
		"x-csrf-protected": true,
	}
	mergeRateLimitExtensions(logoutExt, config, "/logout")

	huma.Register(api, huma.Operation{
		OperationID: "bff-logout",
		Method:      http.MethodPost,
		Path:        config.PathPrefix + "/logout",
		Summary:     "Logout",
		Description: "Clears the session and revokes tokens. Requires valid Origin header for CSRF protection.",
		Tags:        config.Tags,
		Extensions:  logoutExt,
	}, func(ctx context.Context, input *LogoutInput) (*LogoutOutput, error) {
		return &LogoutOutput{
			Body: LogoutResponse{Message: "Logged out successfully"},
		}, nil
	})

	// POST /bff/refresh - Refresh session tokens
	refreshExt := map[string]any{
		"x-internal":       true,
		"x-cookie-auth":    true,
		"x-csrf-protected": true,
	}
	mergeRateLimitExtensions(refreshExt, config, "/refresh")

	huma.Register(api, huma.Operation{
		OperationID: "bff-refresh-session",
		Method:      http.MethodPost,
		Path:        config.PathPrefix + "/refresh",
		Summary:     "Refresh session",
		Description: "Refreshes the access token using the refresh token. Requires valid Origin header for CSRF protection.",
		Tags:        config.Tags,
		Extensions:  refreshExt,
	}, func(ctx context.Context, input *RefreshInput) (*RefreshOutput, error) {
		return &RefreshOutput{
			Body: RefreshResponse{
				Message:   "Session refreshed",
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
		}, nil
	})
}

// mergeRateLimitExtensions adds rate limit extensions to the map.
func mergeRateLimitExtensions(ext map[string]any, config HumaConfig, endpoint string) {
	if !config.IncludeRateLimitDocs || config.Handler == nil || config.Handler.config.RateLimitConfig == nil {
		return
	}

	rlConfig := config.Handler.config.RateLimitConfig
	limit := rlConfig.RequestsPerMinute
	burst := rlConfig.BurstSize

	if epLimit, ok := rlConfig.EndpointLimits[endpoint]; ok {
		limit = epLimit.RequestsPerMinute
		burst = epLimit.BurstSize
	}

	ext["x-ratelimit-limit"] = limit
	ext["x-ratelimit-burst"] = burst
	ext["x-ratelimit-window"] = "1m"
	ext["x-ratelimit-description"] = "Token bucket rate limiting per client IP"
}

// Input/Output types for Huma OpenAPI generation

// GetSessionInput is the input for getting session status.
type GetSessionInput struct{}

// GetSessionOutput is the response for session status.
type GetSessionOutput struct {
	Body SessionStatusResponse
}

// SessionStatusResponse contains session status information.
type SessionStatusResponse struct {
	// Authenticated indicates if the user has a valid session.
	Authenticated bool `json:"authenticated" doc:"Whether the user has a valid session"`

	// UserID is the authenticated user's ID (only present if authenticated).
	UserID *uuid.UUID `json:"user_id,omitempty" doc:"The authenticated user's ID"`

	// OrganizationID is the current organization context (only present if set).
	OrganizationID *uuid.UUID `json:"organization_id,omitempty" doc:"Current organization context"`

	// ExpiresAt is when the session expires (only present if authenticated).
	ExpiresAt *time.Time `json:"expires_at,omitempty" doc:"When the session expires" format:"date-time"`

	// AccessTokenExpiresAt is when the access token expires (only present if authenticated).
	AccessTokenExpiresAt *time.Time `json:"access_token_expires_at,omitempty" doc:"When the access token expires" format:"date-time"`
}

// LogoutInput is the input for logout.
type LogoutInput struct {
	Origin string `header:"Origin" required:"true" doc:"Origin header for CSRF protection"`
}

// LogoutOutput is the response for logout.
type LogoutOutput struct {
	Body LogoutResponse
}

// LogoutResponse contains the logout result.
type LogoutResponse struct {
	// Message indicates the logout result.
	Message string `json:"message" doc:"Logout result message" example:"Logged out successfully"`
}

// RefreshInput is the input for token refresh.
type RefreshInput struct {
	Origin string `header:"Origin" required:"true" doc:"Origin header for CSRF protection"`
}

// RefreshOutput is the response for token refresh.
type RefreshOutput struct {
	Body RefreshResponse

	// Standard rate limit headers
	RateLimitLimit     int   `header:"X-RateLimit-Limit" doc:"Maximum requests per window"`
	RateLimitRemaining int   `header:"X-RateLimit-Remaining" doc:"Requests remaining in current window"`
	RateLimitReset     int64 `header:"X-RateLimit-Reset" doc:"Unix timestamp when window resets"`
}

// RefreshResponse contains the refresh result.
type RefreshResponse struct {
	// Message indicates the refresh result.
	Message string `json:"message" doc:"Refresh result message" example:"Session refreshed"`

	// ExpiresAt is the Unix timestamp when the new access token expires.
	ExpiresAt int64 `json:"expires_at" doc:"Unix timestamp when access token expires"`
}

// BFFErrorResponse is returned for BFF-specific errors.
type BFFErrorResponse struct {
	// Error is the error code.
	Error string `json:"error" doc:"Error code" example:"session_expired"`

	// Message is the human-readable error message.
	Message string `json:"message" doc:"Human-readable error message" example:"Your session has expired"`
}

// Common error codes for documentation
const (
	// ErrCodeNoSession indicates no session cookie was provided.
	ErrCodeNoSession = "no_session"
	// ErrCodeSessionExpired indicates the session has expired.
	ErrCodeSessionExpired = "session_expired"
	// ErrCodeInvalidSession indicates the session is invalid.
	ErrCodeInvalidSession = "invalid_session"
	// ErrCodeCSRFViolation indicates CSRF protection blocked the request.
	ErrCodeCSRFViolation = "csrf_violation"
	// ErrCodeRateLimited indicates rate limit was exceeded.
	ErrCodeRateLimited = "rate_limited"
)

// AddBFFSecurityScheme adds the BFF cookie-based security scheme to the OpenAPI spec.
func AddBFFSecurityScheme(api huma.API, cookieName string) {
	if cookieName == "" {
		cookieName = DefaultCookieName
	}

	api.OpenAPI().Components.SecuritySchemes["bff-session"] = &huma.SecurityScheme{
		Type: "apiKey",
		In:   "cookie",
		Name: cookieName,
		Description: `HTTP-only session cookie for BFF authentication.
This cookie is set automatically after OAuth login and cannot be accessed by JavaScript.
The cookie identifies a server-side session that contains the actual OAuth tokens.`,
		Extensions: map[string]any{
			"x-cookie-httponly": true,
			"x-cookie-secure":   true,
			"x-cookie-samesite": "Strict",
		},
	}
}
