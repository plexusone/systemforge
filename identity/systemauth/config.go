package systemauth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/invopop/jsonschema"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/credential"
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

	// Authz selects the authorization mode (ADR-008): "rbac" (the default)
	// or "rebac" with an engine. SystemAuth does not build the provider
	// from it: the application passes it to authz/mode.New, so the
	// configuration file stays one document.
	Authz authz.ModeConfig `json:"authz,omitempty" yaml:"authz,omitempty" jsonschema:"description=Authorization mode and relationship engine"`

	// ManagedPrincipals configures managed principals; nil disables them.
	ManagedPrincipals *ManagedPrincipalsConfig `json:"managed_principals,omitempty" yaml:"managed_principals,omitempty" jsonschema:"description=Managed principal configuration (humans without an email)"`

	// Connections enables organizations' connections to external services
	// (ADR-017); nil disables them. It needs a database.
	Connections *ConnectionsConfig `json:"connections,omitempty" yaml:"connections,omitempty" jsonschema:"description=Connections to external services (ADR-017)"`

	// Console serves the organization console under /console (ADR-018);
	// nil disables it. It signs in with social login's session.
	Console *ConsoleConfig `json:"console,omitempty" yaml:"console,omitempty" jsonschema:"description=Organization console under /console (ADR-018)"`

	// DPoP tunes DPoP proof checking (RFC 9449). DPoP itself is always on:
	// every client must prove possession of a key at the token endpoint and
	// gets tokens bound to it, unless its registration sets
	// allow_bearer_tokens.
	DPoP DPoPConfig `json:"dpop,omitempty" yaml:"dpop,omitempty" jsonschema:"description=DPoP proof checking (RFC 9449)"`

	// OAuth enables optional OAuth grants.
	OAuth OAuthConfig `json:"oauth,omitempty" yaml:"oauth,omitempty" jsonschema:"description=Optional OAuth grants"`

	// Production waives, by name, production checks that otherwise refuse
	// to start the packaged service (systemauthsvc) or refuse requests.
	Production ProductionConfig `json:"production,omitempty" yaml:"production,omitempty" jsonschema:"description=Named waivers of production checks"`
}

// Names of the production checks a deployment may waive with
// production.allow. Each waiver is logged at startup.
const (
	// AllowEphemeralHMACSecret starts without tokens.hmac_secret: a secret
	// is generated per process, so refresh tokens and authorization codes
	// stop validating after a restart and on other instances.
	AllowEphemeralHMACSecret = "ephemeral_hmac_secret" //nolint:gosec // G101: the name of a check, not a credential

	// AllowClientSecretClientCredentials serves the client_credentials
	// grant to clients that authenticate with a shared client secret.
	// Service accounts with the JWT-bearer grant replace it.
	AllowClientSecretClientCredentials = "client_secret_client_credentials"

	// AllowBearerTokenClients serves clients registered with
	// allow_bearer_tokens, which get access tokens not bound to a DPoP key.
	AllowBearerTokenClients = "bearer_token_clients"
)

// productionAllowances are the names production.allow accepts.
var productionAllowances = []string{AllowEphemeralHMACSecret, AllowClientSecretClientCredentials, AllowBearerTokenClients}

// ProductionConfig waives production checks by name.
type ProductionConfig struct {
	// Allow names the production checks to waive: ephemeral_hmac_secret,
	// client_secret_client_credentials or bearer_token_clients. An unknown
	// name is a configuration error.
	Allow []string `json:"allow,omitempty" yaml:"allow,omitempty" jsonschema:"enum=ephemeral_hmac_secret,enum=client_secret_client_credentials,enum=bearer_token_clients,description=Production checks to waive (each is logged at startup)"`
}

// Allows reports whether the production check name is waived.
func (c ProductionConfig) Allows(name string) bool {
	return slices.Contains(c.Allow, name)
}

func (c ProductionConfig) validate() error {
	for _, name := range c.Allow {
		if !slices.Contains(productionAllowances, name) {
			return fmt.Errorf("%w: production.allow: unknown check %q (want one of %s)", ErrInvalidConfig, name, strings.Join(productionAllowances, ", "))
		}
	}
	return nil
}

// OAuthConfig enables optional OAuth grants.
type OAuthConfig struct {
	// JWTBearer configures the JWT-bearer grant for service accounts.
	JWTBearer JWTBearerConfig `json:"jwt_bearer,omitempty" yaml:"jwt_bearer,omitempty" jsonschema:"description=JWT-bearer grant for service accounts (RFC 7523)"`
}

// JWTBearerConfig configures the JWT-bearer grant (RFC 7523 section 2.1):
// a service account exchanges an assertion it signed with its private key
// for a short-lived DPoP-bound access token, with no refresh token. The
// assertion's issuer and subject are the account's identifier, its
// audience the token endpoint or the issuer, and exp, iat and jti are
// required. Every request must carry a DPoP proof; no client exception
// applies.
type JWTBearerConfig struct {
	// Enabled turns the grant on and advertises it in discovery.
	// Default: false.
	Enabled bool `json:"enabled,omitempty" yaml:"enabled,omitempty" jsonschema:"default=false,description=Accept the JWT-bearer grant for service accounts"`

	// MaxAssertionLifetime is the longest an assertion may be valid,
	// from its iat to its exp. Default: 5 minutes.
	MaxAssertionLifetime Duration `json:"max_assertion_lifetime,omitempty" yaml:"max_assertion_lifetime,omitempty" jsonschema:"default=5m,description=Longest assertion lifetime from iat to exp (e.g. 5m)"`

	// TokenLifetime is the lifetime of the access tokens the grant
	// issues, at most accesschange.MaxAccessTokenLifetime (15 minutes).
	// Default: 15 minutes.
	TokenLifetime Duration `json:"token_lifetime,omitempty" yaml:"token_lifetime,omitempty" jsonschema:"default=15m,description=Access token lifetime for the grant (e.g. 15m; at most 15m)"`
}

// JSONSchemaExtend replaces the shared Duration examples, several of which
// these limits refuse, with values the grant accepts.
func (JWTBearerConfig) JSONSchemaExtend(s *jsonschema.Schema) {
	for name, examples := range map[string][]any{
		"max_assertion_lifetime": {"1m", "5m"},
		"token_lifetime":         {"5m", "15m"},
	} {
		if prop, ok := s.Properties.Get(name); ok && prop != nil {
			prop.Examples = examples
		}
	}
}

// Defaults of JWTBearerConfig.
const (
	DefaultJWTBearerMaxAssertionLifetime = 5 * time.Minute
	DefaultJWTBearerTokenLifetime        = 15 * time.Minute
)

func (c *JWTBearerConfig) applyDefaults() {
	if c.MaxAssertionLifetime == 0 {
		c.MaxAssertionLifetime = Duration(DefaultJWTBearerMaxAssertionLifetime)
	}
	if c.TokenLifetime == 0 {
		c.TokenLifetime = Duration(DefaultJWTBearerTokenLifetime)
	}
}

func (c *JWTBearerConfig) validate() error {
	if c.MaxAssertionLifetime < 0 {
		return fmt.Errorf("%w: oauth.jwt_bearer.max_assertion_lifetime must not be negative", ErrInvalidConfig)
	}
	if d := c.TokenLifetime.Duration(); d < 0 || d > accesschange.MaxAccessTokenLifetime {
		return fmt.Errorf("%w: oauth.jwt_bearer.token_lifetime must be between 0 and %s", ErrInvalidConfig, accesschange.MaxAccessTokenLifetime)
	}
	return nil
}

// DPoPConfig tunes how SystemAuth checks DPoP proofs. The replay cache is
// set with WithDPoPReplayCache.
type DPoPConfig struct {
	// ProofMaxAge is how old a proof's iat may be. Default: 5 minutes.
	ProofMaxAge Duration `json:"proof_max_age,omitempty" yaml:"proof_max_age,omitempty" jsonschema:"default=5m,description=Maximum age of a DPoP proof"`

	// ClockSkew is how far a proof's iat may be in the future, and is added
	// to ProofMaxAge. Default: 30 seconds.
	ClockSkew Duration `json:"clock_skew,omitempty" yaml:"clock_skew,omitempty" jsonschema:"default=30s,description=Allowed clock skew of DPoP proofs"`

	// RequireNonce makes every proof carry a nonce SystemAuth issued
	// (RFC 9449 §8): a proof without one is refused with use_dpop_nonce
	// and a DPoP-Nonce header the client retries with. It requires
	// NonceSecret.
	RequireNonce bool `json:"require_nonce,omitempty" yaml:"require_nonce,omitempty" jsonschema:"default=false,description=Require server-provided DPoP nonces"`

	// NonceSecret keys the nonces: at least 32 bytes, the same on every
	// instance. Supports environment variable expansion:
	// ${SYSTEMAUTH_DPOP_NONCE_SECRET}.
	NonceSecret string `json:"nonce_secret,omitempty" yaml:"nonce_secret,omitempty" jsonschema:"description=Secret keying DPoP nonces (32+ bytes; supports env var expansion)"`

	// NonceLifetime is how long a nonce is accepted. Default: 5 minutes.
	NonceLifetime Duration `json:"nonce_lifetime,omitempty" yaml:"nonce_lifetime,omitempty" jsonschema:"default=5m,description=How long a DPoP nonce is accepted"`

	// ReplayCacheRedisURL is a Redis URL (redis://user:pass@host:6379/0)
	// for the cache that rejects replayed proofs, shared by every
	// instance. The packaged service (systemauthsvc) connects to it; an
	// embedding application passes WithDPoPReplayCache instead. Empty
	// keeps the cache in memory, which suits a single instance. Supports
	// environment variable expansion: ${SYSTEMAUTH_DPOP_REDIS_URL}.
	ReplayCacheRedisURL string `json:"replay_cache_redis_url,omitempty" yaml:"replay_cache_redis_url,omitempty" jsonschema:"description=Redis URL of the shared DPoP replay cache (supports env var expansion)"`

	// SingleInstance declares that one instance serves SystemAuth, so the
	// in-memory replay cache sees every proof. In production the packaged
	// service (systemauthsvc) requires it, ReplayCacheRedisURL or an
	// injected cache: with several instances and per-instance caches, a
	// proof replayed to another instance is accepted.
	SingleInstance bool `json:"single_instance,omitempty" yaml:"single_instance,omitempty" jsonschema:"default=false,description=One instance serves SystemAuth, so the in-memory DPoP replay cache is enough"`

	// ResourceBaseURL is the external base URL of the routes this server
	// protects outside SystemAuth's own endpoints (BearerAccess,
	// BearerPrincipal, Middleware): a DPoP proof's htu must equal it plus
	// the request path as this server sees it. Default: the issuer's
	// origin (scheme and host). Set it when a proxy maps the external path
	// to another one, for example "https://example.com/api" when the proxy
	// strips /api. SystemAuth's own endpoints are always checked against
	// the issuer URL.
	ResourceBaseURL string `json:"resource_base_url,omitempty" yaml:"resource_base_url,omitempty" jsonschema:"description=External base URL of protected routes for DPoP htu (default: the issuer origin)"`
}

// ConsoleConfig configures the organization console (ADR-018).
type ConsoleConfig struct {
	// WebDir holds the console's built pages, such as the output of
	// @plexusone/console. Empty serves only the console's API.
	WebDir string `json:"web_dir,omitempty" yaml:"web_dir,omitempty" jsonschema:"description=Directory of the console's built pages; empty serves only its API"`
}

// ErrInvalidConsoleConfig is returned for a console that cannot work.
var ErrInvalidConsoleConfig = errors.New("systemauth: invalid console configuration")

// ConnectionsConfig configures connections to external services. Their
// credentials are sealed under keys kept in KeysDir, whose root key and the
// deployment's own secrets (such as OAuth client secrets) are read from the
// vault.
type ConnectionsConfig struct {
	// KeysDir holds the key ring and its registry. Back it up; without it
	// stored credentials cannot be read.
	KeysDir string `json:"keys_dir" yaml:"keys_dir" jsonschema:"required,description=Directory holding the key ring and its registry"`

	// Vault is an omnivault URI for the deployment's secret store, for
	// example env:// or file:///etc/systemauth/secrets.
	Vault string `json:"vault" yaml:"vault" jsonschema:"required,description=omnivault URI of the deployment secret store such as env:// or file:///dir"`

	// RootKey is the path in the vault of the key ring's root key: 32 bytes
	// as base64 or hex, for example the output of openssl rand -base64 32.
	RootKey string `json:"root_key" yaml:"root_key" jsonschema:"required,description=Path in the vault of the key ring's 32-byte root key"`

	// EgressAllowPrefixes lists address ranges in CIDR notation, such as
	// 127.0.0.0/8, that provider requests may reach although they are not
	// public. For development against local fakes only: list just the
	// ranges the fakes use. Link-local and cloud metadata addresses are
	// refused even when listed.
	EgressAllowPrefixes []string `json:"egress_allow_prefixes,omitempty" yaml:"egress_allow_prefixes,omitempty" jsonschema:"description=Development only: CIDR ranges provider requests may reach although not public (link-local and metadata addresses are always refused)"`

	// AllowHTTPEgress lets provider requests use plain HTTP. For
	// development against local fakes only.
	AllowHTTPEgress bool `json:"allow_http_egress,omitempty" yaml:"allow_http_egress,omitempty" jsonschema:"description=Development only: allow provider requests over plain HTTP"`
}

// EgressPrefixes parses EgressAllowPrefixes.
func (c *ConnectionsConfig) EgressPrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.EgressAllowPrefixes))
	for _, s := range c.EgressAllowPrefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%w: egress_allow_prefixes: %w", ErrInvalidConnectionsConfig, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// ErrInvalidConnectionsConfig is returned for an incomplete connections
// section.
var ErrInvalidConnectionsConfig = errors.New("systemauth: invalid connections configuration")

func (c *ConnectionsConfig) validate() error {
	for name, v := range map[string]string{"keys_dir": c.KeysDir, "vault": c.Vault, "root_key": c.RootKey} {
		if v == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidConnectionsConfig, name)
		}
	}
	if _, err := c.EgressPrefixes(); err != nil {
		return err
	}
	return nil
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

	// SignupMinimumAge, when set, asks a person their birth month and year
	// before an upstream login creates their account, and refuses anyone
	// younger, keeping nothing about them. Existing accounts are not asked.
	// Default: 0, no question.
	SignupMinimumAge int `json:"signup_minimum_age,omitempty" yaml:"signup_minimum_age,omitempty" jsonschema:"default=0,minimum=0,maximum=120,description=Minimum age to create an account; 0 asks no age"`

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

	// KeyID is the "kid" published in the JWKS and set on every JWT.
	// Default: the RFC 7638 thumbprint of the key.
	//
	// A token's kid selects the key that verifies it: KeyID selects the
	// signing key, a VerificationKeys entry selects that key, and any other
	// kid is refused. Rotate in two deploys, keeping the current key N and
	// the previous key N-1:
	//
	//  1. Pre-stage: add the new key N to VerificationKeys while N-1 still
	//     signs. Relying parties pick N up from the JWKS before any token
	//     signed by it exists.
	//  2. Promote: make N the signing key, move N-1 into VerificationKeys,
	//     and drop N-2. Rolling this deploy back to step 1 keeps verifying
	//     the tokens N signed meanwhile.
	//
	// Never drop N-1 in the deploy that promotes N: tokens it signed are
	// still in use until they expire.
	KeyID string `json:"key_id,omitempty" yaml:"key_id,omitempty" jsonschema:"description=JWKS key ID (default: RFC 7638 thumbprint of the key)"`

	// VerificationKeys are keys published in the JWKS and accepted when
	// verifying tokens, but never used to sign: the previous signing key
	// N-1 after a rotation, and a pre-staged next key N+1 before it is
	// promoted. See KeyID for the rotation steps.
	VerificationKeys []VerificationKeyConfig `json:"verification_keys,omitempty" yaml:"verification_keys,omitempty" jsonschema:"description=Previous or pre-staged keys published in the JWKS for verification only"`

	// PrivateKeyFile is the path of a PEM-encoded RSA private key (PKCS#1
	// or PKCS#8, at least 2048 bits). Supports environment variable
	// expansion: ${SYSTEMAUTH_SIGNING_KEY_FILE}
	PrivateKeyFile string `json:"private_key_file,omitempty" yaml:"private_key_file,omitempty" jsonschema:"description=Path of the PEM RSA signing key (supports env var expansion)"`

	// PrivateKeyPEM is a PEM-encoded RSA private key, normally injected from
	// a secret: ${SYSTEMAUTH_SIGNING_KEY}. Mutually exclusive with
	// PrivateKeyFile.
	PrivateKeyPEM string `json:"private_key_pem,omitempty" yaml:"private_key_pem,omitempty" jsonschema:"description=PEM RSA signing key, usually ${SYSTEMAUTH_SIGNING_KEY} (supports env var expansion)"`

	// PrivateKey is an optional pre-configured RSA private key. When nil,
	// PrivateKeyPEM or PrivateKeyFile is loaded; when none is set an
	// ephemeral key is generated (development only).
	// This field is not serialized - for programmatic use only.
	PrivateKey *rsa.PrivateKey `json:"-" yaml:"-" jsonschema:"-"`
}

// VerificationKeyConfig is an RSA key SystemAuth publishes and verifies
// with but does not sign with. Give exactly one of PublicKeyPEM,
// PublicKeyFile or PublicKey. The PEM may be a public key (PKIX "PUBLIC
// KEY" or PKCS#1 "RSA PUBLIC KEY") or a private key, of which only the
// public part is used, so the file of a pre-staged key can be the one it
// signs with once promoted.
type VerificationKeyConfig struct {
	// KeyID is the key's "kid". Default: the RFC 7638 thumbprint of the
	// key, which is also the default KeyID of a signing key.
	KeyID string `json:"key_id,omitempty" yaml:"key_id,omitempty" jsonschema:"description=Key ID (default: RFC 7638 thumbprint of the key)"`

	// PublicKeyFile is the path of the PEM-encoded key. Supports
	// environment variable expansion.
	PublicKeyFile string `json:"public_key_file,omitempty" yaml:"public_key_file,omitempty" jsonschema:"description=Path of the PEM RSA key (supports env var expansion)"`

	// PublicKeyPEM is the PEM-encoded key. Supports a whole-value
	// environment variable reference such as ${SYSTEMAUTH_PREVIOUS_KEY}.
	PublicKeyPEM string `json:"public_key_pem,omitempty" yaml:"public_key_pem,omitempty" jsonschema:"description=PEM RSA key (supports env var expansion)"`

	// PublicKey is the key, for programmatic use; it is not serialized.
	PublicKey *rsa.PublicKey `json:"-" yaml:"-" jsonschema:"-"`
}

// TokenConfig configures token lifetimes.
// Durations are specified as strings: "15m", "1h", "7d", etc.
type TokenConfig struct {
	// AccessTokenLifetime is how long access tokens are valid. It is the
	// fallback bound on how long an access change can go unseen by a
	// relying party (ADR-010), so it may not exceed
	// accesschange.MaxAccessTokenLifetime (15 minutes).
	// Default: 10 minutes
	AccessTokenLifetime Duration `json:"access_token_lifetime,omitempty" yaml:"access_token_lifetime,omitempty" jsonschema:"default=10m,description=Access token lifetime (e.g. 10m; at most 15m)"`

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

	// HMACSecret keys the HMAC that signs authorization codes, refresh
	// tokens and opaque access tokens: at least 32 bytes, the same on every
	// instance and across restarts. Unset, a random secret is generated at
	// each start, so those tokens stop validating after a restart and on
	// other instances. Supports env var expansion.
	HMACSecret string `json:"hmac_secret,omitempty" yaml:"hmac_secret,omitempty" jsonschema:"description=Secret signing codes and refresh and opaque tokens (32+ bytes; supports env var expansion)"`

	// HMACVerificationSecret is a second secret whose tokens are accepted
	// but never signed: during a rotation, the next secret while it is
	// pre-staged, then the previous one once the next is promoted to
	// HMACSecret, so a rollback never rejects tokens already issued.
	// Requires HMACSecret.
	HMACVerificationSecret string `json:"hmac_verification_secret,omitempty" yaml:"hmac_verification_secret,omitempty" jsonschema:"description=Second HMAC secret accepted but not signed with, during a rotation (32+ bytes; supports env var expansion)"`
}

// MinHMACSecretLength is the shortest TokenConfig.HMACSecret accepted.
const MinHMACSecretLength = 32

func (c *TokenConfig) validate() error {
	if c.HMACSecret != "" && len(c.HMACSecret) < MinHMACSecretLength {
		return fmt.Errorf("%w: tokens.hmac_secret must be at least %d bytes", ErrInvalidConfig, MinHMACSecretLength)
	}
	if c.HMACVerificationSecret == "" {
		return nil
	}
	switch {
	case c.HMACSecret == "":
		return fmt.Errorf("%w: tokens.hmac_verification_secret requires tokens.hmac_secret", ErrInvalidConfig)
	case len(c.HMACVerificationSecret) < MinHMACSecretLength:
		return fmt.Errorf("%w: tokens.hmac_verification_secret must be at least %d bytes", ErrInvalidConfig, MinHMACSecretLength)
	case c.HMACVerificationSecret == c.HMACSecret:
		return fmt.Errorf("%w: tokens.hmac_verification_secret must differ from tokens.hmac_secret", ErrInvalidConfig)
	}
	return nil
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
	AccessTokenLifetime *Duration `json:"access_token_lifetime,omitempty" yaml:"access_token_lifetime,omitempty" jsonschema:"description=Client-specific access token lifetime; capped at 15m"`

	// RefreshTokenLifetime overrides the default for this client.
	RefreshTokenLifetime *Duration `json:"refresh_token_lifetime,omitempty" yaml:"refresh_token_lifetime,omitempty" jsonschema:"description=Client-specific refresh token lifetime"`

	// ManagedPrincipals allows this client to create and sign in managed
	// principals (humans without an email, ADR-005). It takes effect only
	// when the deployment's managed_principals.enabled is also set.
	ManagedPrincipals bool `json:"managed_principals,omitempty" yaml:"managed_principals,omitempty" jsonschema:"description=Allow this client to create and sign in managed principals"`

	// BackchannelLogoutURI is where SystemAuth sends this client OIDC
	// Back-Channel Logout tokens, which also carry access-change events
	// (ADR-010). An https URL; http only for loopback hosts.
	BackchannelLogoutURI string `json:"backchannel_logout_uri,omitempty" yaml:"backchannel_logout_uri,omitempty" jsonschema:"description=Endpoint for back-channel logout and access-change events"`

	// LoginTokenTTL overrides the deployment's default lifetime of reusable
	// login tokens issued for this client's managed principals, for example
	// a school year. It never exceeds managed_principals.login_token_max_ttl.
	LoginTokenTTL *Duration `json:"login_token_ttl,omitempty" yaml:"login_token_ttl,omitempty" jsonschema:"description=Client-specific default lifetime of reusable login tokens (e.g. 7200h)"`

	// AllowBearerTokens is a legacy exception that lets this client get
	// unbound bearer tokens by calling the token endpoint without a DPoP
	// proof. By default every client must send a proof and gets tokens
	// bound to its key (RFC 9449 client metadata dpop_bound_access_tokens
	// true). With it set, a request that does carry a proof still gets
	// bound tokens. Use it only for a client that cannot do DPoP yet:
	// bearer tokens work for whoever holds them.
	AllowBearerTokens bool `json:"allow_bearer_tokens,omitempty" yaml:"allow_bearer_tokens,omitempty" jsonschema:"default=false,description=Legacy exception: allow unbound bearer tokens for this client"`
}

// ManagedPrincipalsConfig configures managed principals: humans without an
// email who always have a manager with one (ADR-005). They are disabled
// unless Enabled is set here and on the requesting client.
type ManagedPrincipalsConfig struct {
	// Enabled allows managed principals in this deployment.
	Enabled bool `json:"enabled" yaml:"enabled" jsonschema:"description=Allow managed principals in this deployment"`

	// LoginTokenTTL is the default lifetime of a reusable login token when
	// neither the request nor the client sets one.
	LoginTokenTTL Duration `json:"login_token_ttl,omitempty" yaml:"login_token_ttl,omitempty" jsonschema:"default=720h,description=Default lifetime of reusable login tokens"`

	// LoginTokenMaxTTL caps the lifetime of every login token; longer
	// requests are clamped.
	LoginTokenMaxTTL Duration `json:"login_token_max_ttl,omitempty" yaml:"login_token_max_ttl,omitempty" jsonschema:"default=9600h,description=Maximum lifetime of any login token"`

	// SingleUseTokenTTL is the default lifetime of a single-use login token.
	SingleUseTokenTTL Duration `json:"single_use_token_ttl,omitempty" yaml:"single_use_token_ttl,omitempty" jsonschema:"default=20m,description=Default lifetime of single-use login tokens"`
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
			AccessTokenLifetime:          Duration(accesschange.DefaultAccessTokenLifetime),
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
		OAuth: OAuthConfig{
			JWTBearer: JWTBearerConfig{
				MaxAssertionLifetime: Duration(DefaultJWTBearerMaxAssertionLifetime),
				TokenLifetime:        Duration(DefaultJWTBearerTokenLifetime),
			},
		},
	}
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.Issuer == "" {
		return ErrMissingIssuer
	}
	if d := c.Tokens.AccessTokenLifetime.Duration(); d < 0 || d > accesschange.MaxAccessTokenLifetime {
		return fmt.Errorf("%w: tokens.access_token_lifetime must be between 0 and %s", ErrInvalidConfig, accesschange.MaxAccessTokenLifetime)
	}
	if abs := c.Tokens.RefreshTokenAbsoluteLifetime; abs != 0 && abs < c.Tokens.RefreshTokenLifetime {
		return fmt.Errorf("%w: tokens.refresh_token_absolute_lifetime must be at least refresh_token_lifetime", ErrInvalidConfig)
	}
	if err := c.Tokens.validate(); err != nil {
		return err
	}
	if c.SocialLogin != nil {
		if err := c.SocialLogin.validate(); err != nil {
			return err
		}
	}
	if c.Connections != nil {
		if err := c.Connections.validate(); err != nil {
			return err
		}
	}
	if err := c.DPoP.validate(); err != nil {
		return err
	}
	if err := c.OAuth.JWTBearer.validate(); err != nil {
		return err
	}
	if err := c.Production.validate(); err != nil {
		return err
	}
	for _, cl := range c.Clients {
		if cl.ID == JWTBearerClientID {
			return fmt.Errorf("%w: client ID %q is reserved", ErrInvalidConfig, JWTBearerClientID)
		}
	}
	if c.Console != nil && c.SocialLogin == nil {
		return fmt.Errorf("%w: the console signs in with social login, which is not configured", ErrInvalidConsoleConfig)
	}
	// A configuration that never called ApplyDefaults has no mode, which
	// means rbac; a stated mode is checked as written.
	az := c.Authz
	az.ApplyDefaults()
	if err := az.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return nil
}

func (c *DPoPConfig) validate() error {
	if c.ProofMaxAge < 0 || c.ClockSkew < 0 || c.NonceLifetime < 0 {
		return fmt.Errorf("%w: dpop durations must not be negative", ErrInvalidConfig)
	}
	if c.RequireNonce && len(c.NonceSecret) < 32 {
		return fmt.Errorf("%w: dpop.require_nonce needs a dpop.nonce_secret of at least 32 bytes", ErrInvalidConfig)
	}
	if c.ResourceBaseURL != "" {
		u, err := url.Parse(c.ResourceBaseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("%w: dpop.resource_base_url must be an http(s) URL without query or fragment", ErrInvalidConfig)
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

	c.Authz.ApplyDefaults()
	c.OAuth.JWTBearer.applyDefaults()

	if mp := c.ManagedPrincipals; mp != nil {
		if mp.LoginTokenTTL == 0 {
			mp.LoginTokenTTL = Duration(credential.DefaultLoginTokenTTL)
		}
		if mp.LoginTokenMaxTTL == 0 {
			mp.LoginTokenMaxTTL = Duration(credential.DefaultLoginTokenMaxTTL)
		}
		if mp.SingleUseTokenTTL == 0 {
			mp.SingleUseTokenTTL = Duration(credential.DefaultSingleUseLoginTokenTTL)
		}
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
