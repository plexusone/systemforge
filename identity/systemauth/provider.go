package systemauth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// This file defines provider interfaces that abstract SystemAuth's functionality.
// These interfaces allow swapping between embedded implementation and external
// services like Ory Hydra/Kratos.
//
// Provider mapping:
//   - IdentityProvider    → Ory Kratos (identities)
//   - AuthenticationProvider → Ory Kratos (sessions)
//   - OAuthProvider       → Ory Hydra (OAuth 2.0/OIDC)
//   - OAuthClientStore    → Ory Hydra (client management)

// ============================================================================
// Identity Provider (maps to Kratos identities)
// ============================================================================

// IdentityProvider manages user identities (CRUD operations).
// In Ory Kratos, this maps to the identity management API.
type IdentityProvider interface {
	// CreateIdentity creates a new identity.
	CreateIdentity(ctx context.Context, identity *Identity) error

	// GetIdentity retrieves an identity by ID.
	GetIdentity(ctx context.Context, id uuid.UUID) (*Identity, error)

	// GetIdentityByEmail retrieves an identity by email address.
	GetIdentityByEmail(ctx context.Context, email string) (*Identity, error)

	// UpdateIdentity updates an existing identity.
	UpdateIdentity(ctx context.Context, identity *Identity) error

	// DeleteIdentity deletes an identity.
	DeleteIdentity(ctx context.Context, id uuid.UUID) error

	// ListIdentities lists identities with optional filtering.
	ListIdentities(ctx context.Context, filter *IdentityFilter) ([]*Identity, error)
}

// Identity represents a user identity.
// This is a clean abstraction that can map to Kratos identity schema.
type Identity struct {
	// ID is the unique identifier.
	ID uuid.UUID `json:"id"`

	// State is the identity state (active, inactive, etc.).
	State IdentityState `json:"state"`

	// Traits holds identity attributes (email, name, etc.).
	// In Kratos, this maps to the identity traits.
	Traits IdentityTraits `json:"traits"`

	// Metadata holds administrative metadata.
	Metadata map[string]any `json:"metadata,omitempty"`

	// Credentials holds credential information (password hash, etc.).
	// Note: Sensitive data should not be returned in queries.
	Credentials []IdentityCredential `json:"credentials,omitempty"`

	// CreatedAt is when the identity was created.
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the identity was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// IdentityState represents the state of an identity.
type IdentityState string

const (
	IdentityStateActive   IdentityState = "active"
	IdentityStateInactive IdentityState = "inactive"
)

// IdentityTraits holds identity attributes.
type IdentityTraits struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Locale        string `json:"locale,omitempty"`
}

// IdentityCredential represents a credential type.
type IdentityCredential struct {
	Type       CredentialType `json:"type"`
	Identifiers []string      `json:"identifiers,omitempty"`
}

// CredentialType is the type of credential.
type CredentialType string

const (
	CredentialTypePassword CredentialType = "password"
	CredentialTypeOIDC     CredentialType = "oidc"
	CredentialTypeWebAuthn CredentialType = "webauthn"
	CredentialTypeTOTP     CredentialType = "totp"
)

// IdentityFilter for listing identities.
type IdentityFilter struct {
	Email    string
	State    IdentityState
	PageSize int
	Page     int
}

// ============================================================================
// Authentication Provider (maps to Kratos sessions)
// ============================================================================

// AuthenticationProvider manages user authentication sessions.
// In Ory Kratos, this maps to the session management API.
type AuthenticationProvider interface {
	// Authenticate validates credentials and creates a session.
	Authenticate(ctx context.Context, req *AuthenticateRequest) (*AuthSession, error)

	// ValidateSession validates a session token and returns session info.
	ValidateSession(ctx context.Context, sessionToken string) (*AuthSession, error)

	// RefreshSession extends a session's lifetime.
	RefreshSession(ctx context.Context, sessionToken string) (*AuthSession, error)

	// RevokeSession invalidates a session.
	RevokeSession(ctx context.Context, sessionToken string) error

	// RevokeSessions invalidates all sessions for an identity.
	RevokeSessions(ctx context.Context, identityID uuid.UUID) error

	// ListSessions lists active sessions for an identity.
	ListSessions(ctx context.Context, identityID uuid.UUID) ([]*AuthSession, error)
}

// AuthenticateRequest contains authentication credentials.
type AuthenticateRequest struct {
	// Method is the authentication method.
	Method AuthMethod `json:"method"`

	// Identifier is the user identifier (email, username, etc.).
	Identifier string `json:"identifier"`

	// Password is used for password authentication.
	Password string `json:"password,omitempty"`

	// OIDCToken is used for OIDC authentication.
	OIDCToken string `json:"oidc_token,omitempty"`

	// OIDCProvider is the OIDC provider name.
	OIDCProvider string `json:"oidc_provider,omitempty"`

	// DeviceInfo contains device/client information.
	DeviceInfo *DeviceInfo `json:"device_info,omitempty"`
}

// AuthMethod is the authentication method.
type AuthMethod string

const (
	AuthMethodPassword AuthMethod = "password"
	AuthMethodOIDC     AuthMethod = "oidc"
	AuthMethodWebAuthn AuthMethod = "webauthn"
	AuthMethodTOTP     AuthMethod = "totp"
)

// DeviceInfo contains information about the authenticating device.
type DeviceInfo struct {
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	DeviceID  string `json:"device_id,omitempty"`
}

// AuthSession represents an authentication session.
type AuthSession struct {
	// ID is the session ID.
	ID string `json:"id"`

	// Token is the session token (cookie value).
	Token string `json:"token"`

	// IdentityID is the authenticated identity.
	IdentityID uuid.UUID `json:"identity_id"`

	// Identity contains identity details (optional, may be nil).
	Identity *Identity `json:"identity,omitempty"`

	// AuthenticatedAt is when authentication occurred.
	AuthenticatedAt time.Time `json:"authenticated_at"`

	// ExpiresAt is when the session expires.
	ExpiresAt time.Time `json:"expires_at"`

	// AuthenticationMethods used in this session.
	AuthenticationMethods []AuthMethod `json:"authentication_methods,omitempty"`

	// Active indicates if the session is still valid.
	Active bool `json:"active"`

	// DeviceInfo about the session.
	DeviceInfo *DeviceInfo `json:"device_info,omitempty"`
}

// ============================================================================
// OAuth Provider (maps to Hydra OAuth 2.0/OIDC)
// ============================================================================

// OAuthProvider handles OAuth 2.0 / OpenID Connect operations.
// In Ory Hydra, this maps to the public and admin APIs.
type OAuthProvider interface {
	// Authorization endpoint operations
	// These are typically called by the authorization server itself.

	// Authorize handles the authorization request.
	// Returns an authorization code or error.
	Authorize(ctx context.Context, req *OAuthAuthorizeRequest) (*OAuthAuthorizeResponse, error)

	// Token handles token requests (authorization code, refresh, client credentials).
	Token(ctx context.Context, req *OAuthTokenRequest) (*OAuthTokenResponse, error)

	// Introspect validates and returns information about a token.
	Introspect(ctx context.Context, token string, tokenTypeHint string) (*OAuthIntrospection, error)

	// Revoke revokes an access or refresh token.
	Revoke(ctx context.Context, token string, tokenTypeHint string) error

	// UserInfo returns claims about the authenticated user (OIDC).
	UserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error)

	// Consent operations (for login/consent flow)

	// GetConsentRequest retrieves a pending consent request.
	GetConsentRequest(ctx context.Context, challenge string) (*OAuthConsentRequest, error)

	// AcceptConsent accepts a consent request.
	AcceptConsent(ctx context.Context, challenge string, accept *OAuthConsentAccept) (*OAuthConsentResponse, error)

	// RejectConsent rejects a consent request.
	RejectConsent(ctx context.Context, challenge string, reject *OAuthConsentReject) (*OAuthConsentResponse, error)

	// Login operations (for login flow)

	// GetLoginRequest retrieves a pending login request.
	GetLoginRequest(ctx context.Context, challenge string) (*OAuthLoginRequest, error)

	// AcceptLogin accepts a login request.
	AcceptLogin(ctx context.Context, challenge string, accept *OAuthLoginAccept) (*OAuthLoginResponse, error)

	// RejectLogin rejects a login request.
	RejectLogin(ctx context.Context, challenge string, reject *OAuthLoginReject) (*OAuthLoginResponse, error)
}

// OAuthAuthorizeRequest represents an authorization request.
type OAuthAuthorizeRequest struct {
	ClientID            string   `json:"client_id"`
	RedirectURI         string   `json:"redirect_uri"`
	ResponseType        string   `json:"response_type"`
	Scope               string   `json:"scope"`
	State               string   `json:"state"`
	Nonce               string   `json:"nonce,omitempty"`
	CodeChallenge       string   `json:"code_challenge,omitempty"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty"`
	Prompt              string   `json:"prompt,omitempty"`
	MaxAge              int      `json:"max_age,omitempty"`
	UILocales           string   `json:"ui_locales,omitempty"`
	ACRValues           string   `json:"acr_values,omitempty"`
}

// OAuthAuthorizeResponse is the authorization response.
type OAuthAuthorizeResponse struct {
	// Code is the authorization code (for code flow).
	Code string `json:"code,omitempty"`

	// RedirectTo is the URL to redirect the user to.
	RedirectTo string `json:"redirect_to"`

	// Error information if authorization failed.
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// OAuthTokenRequest represents a token request.
type OAuthTokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	CodeVerifier string `json:"code_verifier,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OAuthTokenResponse is the token response.
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OAuthIntrospection is the token introspection response.
type OAuthIntrospection struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Nbf       int64    `json:"nbf,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	Jti       string   `json:"jti,omitempty"`
}

// OAuthUserInfo is the OIDC userinfo response.
type OAuthUserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Picture       string `json:"picture,omitempty"`
	Locale        string `json:"locale,omitempty"`
	Zoneinfo      string `json:"zoneinfo,omitempty"`
}

// OAuthConsentRequest is a pending consent request.
type OAuthConsentRequest struct {
	Challenge       string   `json:"challenge"`
	ClientID        string   `json:"client_id"`
	RequestedScopes []string `json:"requested_scopes"`
	Subject         string   `json:"subject"`
	Skip            bool     `json:"skip"`
}

// OAuthConsentAccept accepts a consent request.
type OAuthConsentAccept struct {
	GrantScopes []string       `json:"grant_scopes"`
	Remember    bool           `json:"remember"`
	RememberFor int            `json:"remember_for,omitempty"`
	Session     *ConsentSession `json:"session,omitempty"`
}

// ConsentSession holds session data for consent.
type ConsentSession struct {
	AccessToken map[string]any `json:"access_token,omitempty"`
	IDToken     map[string]any `json:"id_token,omitempty"`
}

// OAuthConsentReject rejects a consent request.
type OAuthConsentReject struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// OAuthConsentResponse is the consent response.
type OAuthConsentResponse struct {
	RedirectTo string `json:"redirect_to"`
}

// OAuthLoginRequest is a pending login request.
type OAuthLoginRequest struct {
	Challenge       string   `json:"challenge"`
	ClientID        string   `json:"client_id"`
	RequestedScopes []string `json:"requested_scopes"`
	Skip            bool     `json:"skip"`
	Subject         string   `json:"subject,omitempty"`
}

// OAuthLoginAccept accepts a login request.
type OAuthLoginAccept struct {
	Subject     string `json:"subject"`
	Remember    bool   `json:"remember"`
	RememberFor int    `json:"remember_for,omitempty"`
	ACR         string `json:"acr,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
}

// OAuthLoginReject rejects a login request.
type OAuthLoginReject struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// OAuthLoginResponse is the login response.
type OAuthLoginResponse struct {
	RedirectTo string `json:"redirect_to"`
}

// ============================================================================
// OAuth Client Store (maps to Hydra client management)
// ============================================================================

// OAuthClientStore manages OAuth 2.0 clients.
// In Ory Hydra, this maps to the admin client API.
type OAuthClientStore interface {
	// CreateClient creates a new OAuth client.
	CreateClient(ctx context.Context, client *OAuthClient) error

	// GetClient retrieves a client by ID.
	GetClient(ctx context.Context, clientID string) (*OAuthClient, error)

	// UpdateClient updates an existing client.
	UpdateClient(ctx context.Context, client *OAuthClient) error

	// DeleteClient deletes a client.
	DeleteClient(ctx context.Context, clientID string) error

	// ListClients lists all clients.
	ListClients(ctx context.Context) ([]*OAuthClient, error)
}

// OAuthClient represents an OAuth 2.0 client.
type OAuthClient struct {
	// ClientID is the unique client identifier.
	ClientID string `json:"client_id"`

	// ClientSecret is the client secret (hashed in storage).
	ClientSecret string `json:"client_secret,omitempty"`

	// ClientName is the human-readable client name.
	ClientName string `json:"client_name,omitempty"`

	// RedirectURIs are the allowed redirect URIs.
	RedirectURIs []string `json:"redirect_uris"`

	// GrantTypes are the allowed grant types.
	GrantTypes []string `json:"grant_types"`

	// ResponseTypes are the allowed response types.
	ResponseTypes []string `json:"response_types"`

	// Scope is the allowed scope.
	Scope string `json:"scope"`

	// Audience are the allowed audiences.
	Audience []string `json:"audience,omitempty"`

	// TokenEndpointAuthMethod is the authentication method for the token endpoint.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`

	// Public indicates if this is a public client (no secret).
	Public bool `json:"public"`

	// Metadata holds custom client metadata.
	Metadata map[string]any `json:"metadata,omitempty"`

	// CreatedAt is when the client was created.
	CreatedAt time.Time `json:"created_at,omitzero"`

	// UpdatedAt is when the client was last updated.
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}
