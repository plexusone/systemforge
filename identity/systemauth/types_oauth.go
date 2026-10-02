package systemauth

// OAuth 2.0 endpoint input/output types for OpenAPI documentation.
// These types define the request/response schemas for Fosite-handled endpoints.

// AuthorizeInput represents the OAuth 2.0 authorization request parameters.
type AuthorizeInput struct {
	ResponseType        string `query:"response_type" required:"true" enum:"code,token" doc:"OAuth 2.0 response type"`
	ClientID            string `query:"client_id" required:"true" doc:"Client identifier"`
	RedirectURI         string `query:"redirect_uri" doc:"URI to redirect after authorization"`
	Scope               string `query:"scope" doc:"Space-separated list of requested scopes"`
	State               string `query:"state" doc:"Opaque value for CSRF protection"`
	CodeChallenge       string `query:"code_challenge" doc:"PKCE code challenge"`
	CodeChallengeMethod string `query:"code_challenge_method" enum:"S256,plain" doc:"PKCE code challenge method"`
	Nonce               string `query:"nonce" doc:"OpenID Connect nonce for replay protection"`
}

// AuthorizeOutput represents the authorization response (redirect).
type AuthorizeOutput struct {
	Location string `header:"Location" doc:"Redirect URI with authorization code or token"`
}

// TokenInput represents the OAuth 2.0 token request parameters.
// Field names follow OAuth 2.0 specification (RFC 6749).
//
//nolint:gosec // G117: Field names are OAuth 2.0 spec-compliant, not actual secrets
type TokenInput struct {
	GrantType    string `form:"grant_type" required:"true" enum:"authorization_code,refresh_token,client_credentials" doc:"OAuth 2.0 grant type"`
	Code         string `form:"code" doc:"Authorization code (for authorization_code grant)"`
	RedirectURI  string `form:"redirect_uri" doc:"Redirect URI (must match authorization request)"`
	ClientID     string `form:"client_id" doc:"Client identifier (if not using Basic auth)"`
	ClientSecret string `form:"client_secret" doc:"Client secret (if not using Basic auth)"`
	RefreshToken string `form:"refresh_token" doc:"Refresh token (for refresh_token grant)"`
	Scope        string `form:"scope" doc:"Requested scopes (for refresh_token or client_credentials)"`
	CodeVerifier string `form:"code_verifier" doc:"PKCE code verifier"`

	// Basic auth credentials (alternative to form-based client auth)
	Authorization string `header:"Authorization" doc:"Basic authentication header (client_id:client_secret)"`
}

// TokenResponse represents the OAuth 2.0 token response.
// Field names follow OAuth 2.0 specification (RFC 6749).
//
//nolint:gosec // G117: Field names are OAuth 2.0 spec-compliant, not actual secrets
type TokenResponse struct {
	AccessToken  string `json:"access_token" doc:"The access token"`
	TokenType    string `json:"token_type" doc:"Token type (typically 'Bearer')"`
	ExpiresIn    int    `json:"expires_in,omitempty" doc:"Token lifetime in seconds"`
	RefreshToken string `json:"refresh_token,omitempty" doc:"Refresh token for obtaining new access tokens"`
	Scope        string `json:"scope,omitempty" doc:"Granted scopes (may differ from requested)"`
	IDToken      string `json:"id_token,omitempty" doc:"OpenID Connect ID token"`
}

// TokenOutput wraps the token response.
type TokenOutput struct {
	Body TokenResponse
}

// IntrospectInput represents the token introspection request.
type IntrospectInput struct {
	Token         string `form:"token" required:"true" doc:"The token to introspect"`
	TokenTypeHint string `form:"token_type_hint" enum:"access_token,refresh_token" doc:"Hint about the token type"`

	// Client authentication
	Authorization string `header:"Authorization" doc:"Basic authentication header (client_id:client_secret)"`
}

// IntrospectResponse represents the token introspection response.
type IntrospectResponse struct {
	Active    bool   `json:"active" doc:"Whether the token is active"`
	Scope     string `json:"scope,omitempty" doc:"Scopes associated with the token"`
	ClientID  string `json:"client_id,omitempty" doc:"Client that requested the token"`
	Username  string `json:"username,omitempty" doc:"Resource owner username"`
	TokenType string `json:"token_type,omitempty" doc:"Token type"`
	Exp       int64  `json:"exp,omitempty" doc:"Token expiration timestamp"`
	Iat       int64  `json:"iat,omitempty" doc:"Token issue timestamp"`
	Nbf       int64  `json:"nbf,omitempty" doc:"Token not-before timestamp"`
	Sub       string `json:"sub,omitempty" doc:"Subject (user ID)"`
	Aud       string `json:"aud,omitempty" doc:"Intended audience"`
	Iss       string `json:"iss,omitempty" doc:"Token issuer"`
	Jti       string `json:"jti,omitempty" doc:"JWT ID"`
}

// IntrospectOutput wraps the introspection response.
type IntrospectOutput struct {
	Body IntrospectResponse
}

// RevokeInput represents the token revocation request.
type RevokeInput struct {
	Token         string `form:"token" required:"true" doc:"The token to revoke"`
	TokenTypeHint string `form:"token_type_hint" enum:"access_token,refresh_token" doc:"Hint about the token type"`

	// Client authentication
	Authorization string `header:"Authorization" doc:"Basic authentication header (client_id:client_secret)"`
}

// RevokeOutput represents the token revocation response (empty on success).
type RevokeOutput struct{}

// OAuthError represents an OAuth 2.0 error response.
type OAuthError struct {
	Error            string `json:"error" doc:"Error code"`
	ErrorDescription string `json:"error_description,omitempty" doc:"Human-readable error description"`
	ErrorURI         string `json:"error_uri,omitempty" doc:"URI with more information about the error"`
}
