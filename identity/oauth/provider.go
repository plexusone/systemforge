package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"github.com/plexusone/systemforge/identity/ent"
)

// Config holds OAuth 2.0 server configuration.
type Config struct {
	// Issuer is the OAuth/OIDC issuer URL
	Issuer string

	// AccessTokenLifespan is the duration access tokens are valid
	AccessTokenLifespan time.Duration

	// RefreshTokenLifespan is the duration refresh tokens are valid
	RefreshTokenLifespan time.Duration

	// AuthCodeLifespan is the duration authorization codes are valid
	AuthCodeLifespan time.Duration

	// PrivateKey is the RSA private key for signing tokens
	// If nil, a key will be generated
	PrivateKey *rsa.PrivateKey

	// HashSecret is the secret used for HMAC operations
	HashSecret []byte
}

// DefaultConfig returns a default OAuth configuration.
func DefaultConfig(issuer string, hashSecret []byte) *Config {
	return &Config{
		Issuer:               issuer,
		AccessTokenLifespan:  15 * time.Minute,
		RefreshTokenLifespan: 7 * 24 * time.Hour,
		AuthCodeLifespan:     10 * time.Minute,
		HashSecret:           hashSecret,
	}
}

// Provider wraps Fosite and provides OAuth 2.0/OIDC functionality.
type Provider struct {
	oauth2  fosite.OAuth2Provider
	storage *Storage
	config  *Config
	key     *rsa.PrivateKey
}

// NewProvider creates a new OAuth provider.
func NewProvider(db *ent.Client, cfg *Config) (*Provider, error) {
	storage := NewStorage(db)

	// Generate RSA key if not provided
	key := cfg.PrivateKey
	if key == nil {
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	}

	// Build Fosite configuration
	fositeConfig := &fosite.Config{
		AccessTokenLifespan:         cfg.AccessTokenLifespan,
		RefreshTokenLifespan:        cfg.RefreshTokenLifespan,
		AuthorizeCodeLifespan:       cfg.AuthCodeLifespan,
		GlobalSecret:                cfg.HashSecret,
		SendDebugMessagesToClients:  false,
		EnforcePKCE:                 true,
		EnforcePKCEForPublicClients: true,
	}

	// Key getter function for JWT signing
	keyGetter := func(_ context.Context) (interface{}, error) {
		return key, nil
	}

	// Create JWT signer
	jwtSigner := &jwt.DefaultSigner{
		GetPrivateKey: keyGetter,
	}

	// Build OAuth2 provider with all needed components
	oauth2Provider := compose.Compose(
		fositeConfig,
		storage,
		&compose.CommonStrategy{
			CoreStrategy: compose.NewOAuth2HMACStrategy(fositeConfig),
			Signer:       jwtSigner,
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
	)

	return &Provider{
		oauth2:  oauth2Provider,
		storage: storage,
		config:  cfg,
		key:     key,
	}, nil
}

// OAuth2Provider returns the underlying Fosite provider.
func (p *Provider) OAuth2Provider() fosite.OAuth2Provider {
	return p.oauth2
}

// Storage returns the storage adapter.
func (p *Provider) Storage() *Storage {
	return p.storage
}

// Session creates a new OAuth session for subject. The subject is set on
// the session itself, which Fosite reads for introspection and token
// storage, as well as on the ID token claims.
func (p *Provider) Session(subject string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Subject: subject,
		Claims: &jwt.IDTokenClaims{
			Issuer:    p.config.Issuer,
			Subject:   subject,
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(p.config.AccessTokenLifespan),
		},
		Headers: &jwt.Headers{},
	}
}
