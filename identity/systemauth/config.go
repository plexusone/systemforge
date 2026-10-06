package systemauth

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/invopop/jsonschema"
)

// Config holds SystemAuth server configuration.
// This is the root configuration object for both embedded and standalone modes.
type Config struct {
	// Issuer is the OAuth/OIDC issuer URL (required).
	// Example: "https://auth.example.com"
	Issuer string `json:"issuer" yaml:"issuer" jsonschema:"required,format=uri,description=OAuth/OIDC issuer URL"`

	// Database configures persistent storage.
	// If nil, in-memory storage is used (suitable for embedded mode).
	Database *DatabaseConfig `json:"database,omitempty" yaml:"database,omitempty" jsonschema:"description=Database configuration for persistent storage"`

	// Keys configures signing key management.
	Keys KeyConfig `json:"keys,omitempty" yaml:"keys,omitempty" jsonschema:"description=Signing key configuration"`

	// Tokens configures token lifetimes.
	Tokens TokenConfig `json:"tokens,omitempty" yaml:"tokens,omitempty" jsonschema:"description=Token lifetime configuration"`

	// Clients defines statically configured OAuth clients.
	Clients []ClientConfig `json:"clients,omitempty" yaml:"clients,omitempty" jsonschema:"description=Static OAuth client configurations"`

	// Federation configures SystemAuth integration.
	Federation *FederationConfig `json:"federation,omitempty" yaml:"federation,omitempty" jsonschema:"description=SystemAuth federation configuration"`

	// Features enables/disables optional features.
	Features FeatureConfig `json:"features,omitempty" yaml:"features,omitempty" jsonschema:"description=Feature flags"`

	// SocialLogin enables "log in with GitHub/Google" on this server.
	// If nil, no social login routes are mounted.
	SocialLogin *SocialLoginConfig `json:"social_login,omitempty" yaml:"social_login,omitempty" jsonschema:"description=Upstream GitHub/Google social login configuration"`
}

// SocialLoginConfig configures upstream social login (GitHub, Google).
// Upstream client credentials live only in the SystemAuth deployment.
type SocialLoginConfig struct {
	// GitHub configures login with GitHub. Nil disables it.
	GitHub *SocialProviderConfig `json:"github,omitempty" yaml:"github,omitempty" jsonschema:"description=GitHub OAuth app credentials"`

	// Google configures login with Google. Nil disables it.
	Google *SocialProviderConfig `json:"google,omitempty" yaml:"google,omitempty" jsonschema:"description=Google OAuth client credentials"`

	// AllowedRedirectOrigins lists absolute origins (scheme://host[:port])
	// that a post-login return_to URL may point at, in addition to the
	// issuer's own origin. Relative same-origin paths are always allowed.
	AllowedRedirectOrigins []string `json:"allowed_redirect_origins,omitempty" yaml:"allowed_redirect_origins,omitempty" jsonschema:"description=Absolute origins allowed as post-login redirect targets"`

	// DefaultRedirect is where users land after login when no return_to is
	// given. Default: "/".
	DefaultRedirect string `json:"default_redirect,omitempty" yaml:"default_redirect,omitempty" jsonschema:"default=/,description=Post-login redirect when none is requested"`

	// SessionLifetime is the absolute lifetime of the login session cookie.
	// Default: 12h.
	SessionLifetime Duration `json:"session_lifetime,omitempty" yaml:"session_lifetime,omitempty" jsonschema:"default=12h,description=Absolute login session lifetime"`

	// SkipConsent auto-grants consent for authorization requests from users
	// signed in through social login. Use only when every registered client
	// is first-party.
	SkipConsent bool `json:"skip_consent,omitempty" yaml:"skip_consent,omitempty" jsonschema:"default=false,description=Auto-grant consent for first-party clients"`

	// InsecureCookies drops the __Host- prefix and the Secure flag so the
	// login works over plain HTTP. Local development only.
	InsecureCookies bool `json:"insecure_cookies,omitempty" yaml:"insecure_cookies,omitempty" jsonschema:"default=false,description=Development only: allow login cookies over plain HTTP"`
}

// SocialProviderConfig holds upstream OAuth client credentials.
//
//nolint:gosec // G117: Field names are OAuth 2.0 spec-compliant, not actual secrets
type SocialProviderConfig struct {
	// ClientID is the upstream OAuth client ID.
	// Supports environment variable expansion: ${GITHUB_CLIENT_ID}
	ClientID string `json:"client_id" yaml:"client_id" jsonschema:"required,description=Upstream OAuth client ID (supports env var expansion)"`

	// ClientSecret is the upstream OAuth client secret.
	// Supports environment variable expansion: ${GITHUB_CLIENT_SECRET}
	ClientSecret string `json:"client_secret" yaml:"client_secret" jsonschema:"required,description=Upstream OAuth client secret (supports env var expansion)"`

	// RedirectURL overrides the callback URL registered with the provider.
	// Default: {issuer}/login/{provider}/callback
	RedirectURL string `json:"redirect_url,omitempty" yaml:"redirect_url,omitempty" jsonschema:"format=uri,description=Callback URL registered with the provider"`

	// Scopes overrides the default scopes.
	Scopes []string `json:"scopes,omitempty" yaml:"scopes,omitempty" jsonschema:"description=Upstream OAuth scopes"`
}

// DatabaseConfig configures persistent storage.
type DatabaseConfig struct {
	// Driver is the database driver: "postgres", "sqlite", "mysql"
	Driver string `json:"driver" yaml:"driver" jsonschema:"required,enum=postgres,enum=sqlite,enum=mysql,description=Database driver"`

	// DSN is the database connection string.
	// Supports environment variable expansion: ${DATABASE_URL}
	DSN string `json:"dsn" yaml:"dsn" jsonschema:"required,description=Database connection string (supports env var expansion)"`
}

// KeyConfig configures signing key management.
type KeyConfig struct {
	// Algorithm is the signing algorithm: "RS256" (default), "ES256"
	Algorithm string `json:"algorithm,omitempty" yaml:"algorithm,omitempty" jsonschema:"enum=RS256,enum=ES256,default=RS256,description=JWT signing algorithm"`

	// RotationDays is how often to rotate keys (0 = never)
	RotationDays int `json:"rotation_days,omitempty" yaml:"rotation_days,omitempty" jsonschema:"minimum=0,description=Key rotation interval in days (0 = never)"`

	// PrivateKey is an optional pre-configured RSA private key.
	// If nil, a key will be generated automatically.
	// This field is not serialized - for programmatic use only.
	PrivateKey *rsa.PrivateKey `json:"-" yaml:"-" jsonschema:"-"`
}

// TokenConfig configures token lifetimes.
// Durations are specified as strings: "15m", "1h", "7d", etc.
type TokenConfig struct {
	// AccessTokenLifetime is how long access tokens are valid.
	// Default: 15 minutes
	AccessTokenLifetime Duration `json:"access_token_lifetime,omitempty" yaml:"access_token_lifetime,omitempty" jsonschema:"default=15m,description=Access token lifetime (e.g. 15m, 1h)"`

	// RefreshTokenLifetime is how long refresh tokens are valid.
	// Default: 7 days
	RefreshTokenLifetime Duration `json:"refresh_token_lifetime,omitempty" yaml:"refresh_token_lifetime,omitempty" jsonschema:"default=168h,description=Refresh token lifetime (e.g. 168h, 720h)"`

	// RefreshTokenAbsoluteLifetime bounds a refresh-token family: rotation
	// issues a new refresh token on every use, but never past this long
	// after the original grant. After it the user must sign in again.
	// Default: 30 days. Must be at least RefreshTokenLifetime.
	RefreshTokenAbsoluteLifetime Duration `json:"refresh_token_absolute_lifetime,omitempty" yaml:"refresh_token_absolute_lifetime,omitempty" jsonschema:"default=720h,description=Absolute lifetime of a refresh-token family across rotations (e.g. 720h)"`

	// IDTokenLifetime is how long ID tokens are valid.
	// Default: 1 hour
	IDTokenLifetime Duration `json:"id_token_lifetime,omitempty" yaml:"id_token_lifetime,omitempty" jsonschema:"default=1h,description=ID token lifetime (e.g. 1h)"`

	// AuthCodeLifetime is how long authorization codes are valid.
	// Default: 10 minutes
	AuthCodeLifetime Duration `json:"auth_code_lifetime,omitempty" yaml:"auth_code_lifetime,omitempty" jsonschema:"default=10m,description=Authorization code lifetime (e.g. 10m)"`
}

// Duration is a wrapper around time.Duration that supports
// human-readable string serialization (e.g., "15m", "1h", "7d").
type Duration time.Duration

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(d).String() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	// Remove quotes
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (interface{}, error) {
	return time.Duration(d).String(), nil
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(dur)
	return nil
}

// Duration returns the underlying time.Duration.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// JSONSchema implements jsonschema.JSONSchemaer for Duration.
func (Duration) JSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Pattern:     `^(\d+(\.\d+)?(ns|us|µs|ms|s|m|h))+$`,
		Description: "Duration string (e.g., '15m', '1h', '24h')",
		Examples:    []any{"15m", "1h", "168h", "720h"},
	}
}

// ClientConfig defines a statically configured OAuth client.
//
//nolint:gosec // G117: Field names are OAuth 2.0 spec-compliant, not actual secrets
type ClientConfig struct {
	// ID is the client identifier.
	ID string `json:"id" yaml:"id" jsonschema:"required,description=Unique client identifier"`

	// Secret is the client secret (for confidential clients).
	// Supports environment variable expansion: ${CLIENT_SECRET}
	Secret string `json:"secret,omitempty" yaml:"secret,omitempty" jsonschema:"description=Client secret (supports env var expansion)"`

	// Type is "public" or "confidential".
	Type string `json:"type" yaml:"type" jsonschema:"required,enum=public,enum=confidential,description=Client type"`

	// Name is a human-readable name.
	Name string `json:"name" yaml:"name" jsonschema:"required,description=Human-readable client name"`

	// Description is an optional description.
	Description string `json:"description,omitempty" yaml:"description,omitempty" jsonschema:"description=Client description"`

	// RedirectURIs are allowed redirect URIs.
	RedirectURIs []string `json:"redirect_uris,omitempty" yaml:"redirect_uris,omitempty" jsonschema:"description=Allowed redirect URIs"`

	// GrantTypes are allowed grant types.
	// Options: "authorization_code", "refresh_token", "client_credentials"
	GrantTypes []string `json:"grant_types,omitempty" yaml:"grant_types,omitempty" jsonschema:"description=Allowed OAuth grant types"`

	// ResponseTypes are allowed response types.
	// Options: "code", "token"
	ResponseTypes []string `json:"response_types,omitempty" yaml:"response_types,omitempty" jsonschema:"description=Allowed OAuth response types"`

	// Scopes are allowed scopes.
	Scopes []string `json:"scopes,omitempty" yaml:"scopes,omitempty" jsonschema:"description=Allowed OAuth scopes"`

	// Audience restricts the token audience.
	Audience []string `json:"audience,omitempty" yaml:"audience,omitempty" jsonschema:"description=Allowed token audiences"`

	// AccessTokenLifetime overrides the default for this client.
	AccessTokenLifetime *Duration `json:"access_token_lifetime,omitempty" yaml:"access_token_lifetime,omitempty" jsonschema:"description=Client-specific access token lifetime"`

	// RefreshTokenLifetime overrides the default for this client.
	RefreshTokenLifetime *Duration `json:"refresh_token_lifetime,omitempty" yaml:"refresh_token_lifetime,omitempty" jsonschema:"description=Client-specific refresh token lifetime"`
}

// FederationConfig configures SystemAuth integration.
//
//nolint:gosec // G117: Field names are OAuth 2.0 spec-compliant, not actual secrets
type FederationConfig struct {
	// Enabled enables federation mode.
	Enabled bool `json:"enabled" yaml:"enabled" jsonschema:"description=Enable SystemAuth federation"`

	// SystemAuthURL is the SystemAuth server URL.
	SystemAuthURL string `json:"systemauth_url" yaml:"systemauth_url" jsonschema:"format=uri,description=SystemAuth server URL"`

	// AppID is this application's identifier in the federation.
	AppID string `json:"app_id" yaml:"app_id" jsonschema:"description=Application ID in the federation"`

	// ClientID is the OAuth client ID for SystemAuth.
	ClientID string `json:"client_id" yaml:"client_id" jsonschema:"description=OAuth client ID for SystemAuth"`

	// ClientSecret is the OAuth client secret for SystemAuth.
	// Supports environment variable expansion: ${SYSTEMAUTH_SECRET}
	ClientSecret string `json:"client_secret" yaml:"client_secret" jsonschema:"description=OAuth client secret (supports env var expansion)"`
}

// FeatureConfig enables/disables optional features.
type FeatureConfig struct {
	// RequirePKCE requires PKCE for all authorization code flows.
	// Default: true for public clients, configurable for confidential
	RequirePKCE bool `json:"require_pkce,omitempty" yaml:"require_pkce,omitempty" jsonschema:"default=true,description=Require PKCE for authorization code flows"`

	// AllowDynamicRegistration enables RFC 7591 dynamic client registration.
	AllowDynamicRegistration bool `json:"allow_dynamic_registration,omitempty" yaml:"allow_dynamic_registration,omitempty" jsonschema:"default=false,description=Enable dynamic client registration (RFC 7591)"`

	// EnableDeviceFlow enables the device authorization grant (RFC 8628).
	EnableDeviceFlow bool `json:"enable_device_flow,omitempty" yaml:"enable_device_flow,omitempty" jsonschema:"default=false,description=Enable device authorization grant (RFC 8628)"`

	// EnableJWTAccessTokens issues JWT access tokens instead of opaque tokens.
	EnableJWTAccessTokens bool `json:"enable_jwt_access_tokens,omitempty" yaml:"enable_jwt_access_tokens,omitempty" jsonschema:"default=false,description=Issue JWT access tokens instead of opaque tokens"`
}

// DefaultConfig returns a Config with sensible defaults for embedded mode.
func DefaultConfig(issuer string) *Config {
	return &Config{
		Issuer: issuer,
		Keys: KeyConfig{
			Algorithm:    "RS256",
			RotationDays: 0, // No auto-rotation in embedded mode
		},
		Tokens: TokenConfig{
			AccessTokenLifetime:          Duration(15 * time.Minute),
			RefreshTokenLifetime:         Duration(7 * 24 * time.Hour),
			RefreshTokenAbsoluteLifetime: Duration(30 * 24 * time.Hour),
			IDTokenLifetime:              Duration(1 * time.Hour),
			AuthCodeLifetime:             Duration(10 * time.Minute),
		},
		Features: FeatureConfig{
			RequirePKCE:              true,
			AllowDynamicRegistration: false,
			EnableDeviceFlow:         false,
			EnableJWTAccessTokens:    false,
		},
	}
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.Issuer == "" {
		return ErrMissingIssuer
	}
	if abs := c.Tokens.RefreshTokenAbsoluteLifetime; abs != 0 && abs < c.Tokens.RefreshTokenLifetime {
		return fmt.Errorf("%w: tokens.refresh_token_absolute_lifetime must be at least refresh_token_lifetime", ErrInvalidConfig)
	}
	if c.SocialLogin != nil {
		if err := c.SocialLogin.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (c *SocialLoginConfig) validate() error {
	for name, p := range map[string]*SocialProviderConfig{"github": c.GitHub, "google": c.Google} {
		if p != nil && (p.ClientID == "" || p.ClientSecret == "") {
			return fmt.Errorf("%w: %s requires client_id and client_secret", ErrInvalidSocialLoginConfig, name)
		}
	}
	for _, o := range c.AllowedRedirectOrigins {
		if _, err := parseOrigin(o); err != nil {
			return fmt.Errorf("%w: allowed_redirect_origins: %v", ErrInvalidSocialLoginConfig, err)
		}
	}
	return nil
}

// ApplyDefaults fills in missing values with defaults.
func (c *Config) ApplyDefaults() {
	defaults := DefaultConfig(c.Issuer)

	if c.Keys.Algorithm == "" {
		c.Keys.Algorithm = defaults.Keys.Algorithm
	}

	if c.Tokens.AccessTokenLifetime == 0 {
		c.Tokens.AccessTokenLifetime = defaults.Tokens.AccessTokenLifetime
	}
	if c.Tokens.RefreshTokenLifetime == 0 {
		c.Tokens.RefreshTokenLifetime = defaults.Tokens.RefreshTokenLifetime
	}
	if c.Tokens.RefreshTokenAbsoluteLifetime == 0 {
		c.Tokens.RefreshTokenAbsoluteLifetime = defaults.Tokens.RefreshTokenAbsoluteLifetime
		if c.Tokens.RefreshTokenAbsoluteLifetime < c.Tokens.RefreshTokenLifetime {
			c.Tokens.RefreshTokenAbsoluteLifetime = c.Tokens.RefreshTokenLifetime
		}
	}
	if c.Tokens.IDTokenLifetime == 0 {
		c.Tokens.IDTokenLifetime = defaults.Tokens.IDTokenLifetime
	}
	if c.Tokens.AuthCodeLifetime == 0 {
		c.Tokens.AuthCodeLifetime = defaults.Tokens.AuthCodeLifetime
	}

	if c.SocialLogin != nil {
		if c.SocialLogin.DefaultRedirect == "" {
			c.SocialLogin.DefaultRedirect = "/"
		}
		if c.SocialLogin.SessionLifetime == 0 {
			c.SocialLogin.SessionLifetime = Duration(12 * time.Hour)
		}
	}
}
