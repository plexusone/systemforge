package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"

	"github.com/plexusone/systemforge/identity/dpopproof"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/internal/oauthcore"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/session/middleware"
)

// Config holds OAuth 2.0 server configuration.
type Config struct {
	// Issuer is the OAuth/OIDC issuer URL: the external URL clients use,
	// from which the endpoint URLs DPoP proofs must name are built.
	Issuer string

	// AccessTokenLifespan is the duration access tokens are valid
	AccessTokenLifespan time.Duration

	// RefreshTokenLifespan is the duration refresh tokens are valid
	RefreshTokenLifespan time.Duration

	// AuthCodeLifespan is the duration authorization codes are valid
	AuthCodeLifespan time.Duration

	// PrivateKey is the RSA private key for signing tokens (required). It
	// must be the same on every instance and across restarts: tokens and
	// the JWKS are tied to it.
	PrivateKey *rsa.PrivateKey

	// KeyID is the "kid" of PrivateKey, published in the JWKS and set on
	// every JWT. Default: the RFC 7638 thumbprint of the key.
	//
	// A token's kid selects the key that verifies it: KeyID selects the
	// signing key, a VerificationKeys entry selects that key, and any other
	// kid is refused. Rotate keeping the current key N and the previous
	// key N-1, as for SystemAuth (systemauth.KeyConfig.KeyID):
	//
	//  1. Pre-stage: add the new key N to VerificationKeys while N-1 still
	//     signs, so verifiers pick it up from the JWKS first.
	//  2. Promote: make N PrivateKey, move N-1 into VerificationKeys, and
	//     drop N-2.
	//
	// Never drop N-1 in the deploy that promotes N: tokens it signed are
	// still in use until they expire.
	KeyID string

	// VerificationKeys are keys published in the JWKS and accepted when
	// verifying tokens, but never used to sign: the previous signing key
	// N-1 after a rotation, and a pre-staged next key before it is
	// promoted.
	VerificationKeys []systemauth.VerificationKeyConfig

	// AllowEphemeralKey lets NewProvider generate a fresh signing key when
	// PrivateKey is nil. Development and tests only: the key changes on
	// every start and differs between instances, so tokens stop verifying
	// after a restart.
	AllowEphemeralKey bool

	// JWTAccessTokens issues access tokens as RS256 JWTs (RFC 9068, typ
	// at+jwt) signed with PrivateKey, carrying cnf.jkt when DPoP-bound,
	// instead of opaque tokens. Either way tokens are stored, so
	// revocation and introspection work.
	JWTAccessTokens bool

	// HashSecret is the secret used for HMAC operations
	HashSecret []byte

	// DPoP configures DPoP proof checking (RFC 9449).
	DPoP DPoPConfig
}

// DPoPConfig configures how the provider checks DPoP proofs.
type DPoPConfig struct {
	// ProofMaxAge is how old a proof's iat may be. Default: 5 minutes.
	ProofMaxAge time.Duration

	// ClockSkew is how far a proof's iat may be in the future, and is added
	// to ProofMaxAge. Default: 30 seconds.
	ClockSkew time.Duration

	// ReplayCache rejects a proof whose jti was used before. Default: an
	// in-memory cache, which suits a single instance; when several
	// instances serve the provider, pass one they share, such as
	// middleware.NewRedisReplayCache.
	ReplayCache dpopproof.ReplayCache

	// Nonces, when set, requires every proof to carry a server nonce
	// (RFC 9449 §8); see dpopproof.NewNonces.
	Nonces *dpopproof.Nonces
}

// ErrSigningKeyRequired is returned by NewProvider when Config.PrivateKey
// is nil and Config.AllowEphemeralKey is not set.
var ErrSigningKeyRequired = errors.New("oauth: a signing key (Config.PrivateKey) is required")

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
//
// It issues DPoP-bound tokens (RFC 9449) by default, as SystemAuth does:
// every token request must carry a valid DPoP proof, the access token is
// bound to the proof's key (cnf.jkt, token_type DPoP), and so is the
// refresh token. Only a client registered with the allow_bearer_tokens
// exception may call the token endpoint without a proof, and then gets
// unbound bearer tokens.
type Provider struct {
	oauth2       fosite.OAuth2Provider
	storage      *Storage
	config       *Config
	keys         *oauthcore.KeyRing
	codeStrategy oauth2.AuthorizeCodeStrategy
	dpop         *dpopproof.Checker
}

// NewProvider creates a new OAuth provider.
func NewProvider(db *ent.Client, cfg *Config) (*Provider, error) {
	storage := NewStorage(db)

	// A signing key is required; an ephemeral one only when asked for.
	key := cfg.PrivateKey
	if key == nil {
		if !cfg.AllowEphemeralKey {
			return nil, ErrSigningKeyRequired
		}
		var err error
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		slog.Default().Warn("oauth: generated an ephemeral signing key; tokens will not verify after a restart or on another instance")
	}
	keys, err := newKeyRing(key, cfg.KeyID, cfg.VerificationKeys)
	if err != nil {
		return nil, fmt.Errorf("oauth: %w", err)
	}

	checker, err := newDPoPChecker(cfg.DPoP)
	if err != nil {
		return nil, err
	}

	// Build Fosite configuration
	fositeConfig := &fosite.Config{
		AccessTokenIssuer:           cfg.Issuer,
		IDTokenIssuer:               cfg.Issuer,
		AccessTokenLifespan:         cfg.AccessTokenLifespan,
		RefreshTokenLifespan:        cfg.RefreshTokenLifespan,
		AuthorizeCodeLifespan:       cfg.AuthCodeLifespan,
		GlobalSecret:                cfg.HashSecret,
		SendDebugMessagesToClients:  false,
		EnforcePKCE:                 true,
		EnforcePKCEForPublicClients: true,
		// Client secrets are stored as bcrypt or Argon2id hashes.
		ClientSecretsHasher: systemauth.ClientSecretHasher{},
	}

	// JWTs are signed with the signing key and verified with the key their
	// kid selects from the key ring, so tokens signed before a rotation
	// keep verifying and a token with an unknown kid is refused.
	jwtSigner := keys.Signer()

	var coreStrategy oauth2.CoreStrategy = compose.NewOAuth2HMACStrategy(fositeConfig)
	if cfg.JWTAccessTokens {
		coreStrategy = &oauth2.DefaultJWTStrategy{Signer: jwtSigner, HMACSHAStrategy: coreStrategy, Config: fositeConfig}
	}

	// Build OAuth2 provider with all needed components
	oauth2Provider := compose.Compose(
		fositeConfig,
		storage,
		&compose.CommonStrategy{
			CoreStrategy: coreStrategy,
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
		oauth2:       oauth2Provider,
		storage:      storage,
		config:       cfg,
		keys:         keys,
		codeStrategy: coreStrategy,
		dpop:         checker,
	}, nil
}

// newDPoPChecker builds the proof checker for cfg.
func newDPoPChecker(cfg DPoPConfig) (*dpopproof.Checker, error) {
	cache := cfg.ReplayCache
	if cache == nil {
		slog.Default().Warn("oauth: DPoP proofs checked against an in-memory replay cache; set Config.DPoP.ReplayCache to a shared cache when several instances serve the provider")
		cache = middleware.NewMemoryReplayCache()
	}
	checker, err := dpopproof.NewChecker(dpopproof.Config{
		MaxAge:      cfg.ProofMaxAge,
		ClockSkew:   cfg.ClockSkew,
		ReplayCache: cache,
		Nonces:      cfg.Nonces,
	})
	if err != nil {
		return nil, fmt.Errorf("oauth: %w", err)
	}
	return checker, nil
}

// OAuth2Provider returns the underlying Fosite provider.
func (p *Provider) OAuth2Provider() fosite.OAuth2Provider {
	return p.oauth2
}

// Storage returns the storage adapter.
func (p *Provider) Storage() *Storage {
	return p.storage
}

// KeyID returns the kid of the signing key.
func (p *Provider) KeyID() string {
	return p.keys.SigningKeyID()
}

// TokenEndpointURL is the token endpoint as advertised in discovery: the
// htu a proof for a token request must name.
func (p *Provider) TokenEndpointURL() string {
	return p.config.Issuer + "/oauth/token"
}

// issuerOrigin is the scheme and host of the issuer.
func (p *Provider) issuerOrigin() string {
	u, err := url.Parse(p.config.Issuer)
	if err != nil || u.Host == "" {
		return p.config.Issuer
	}
	return u.Scheme + "://" + u.Host
}

// Session creates a new OAuth session for subject. The subject is set on
// the session itself, which Fosite reads for introspection and token
// storage, as well as on the ID token claims. The session carries the
// DPoP binding of the grant (DPoPJKT) and, with JWTAccessTokens, the
// claims and header of JWT access tokens.
func (p *Provider) Session(subject string) *systemauth.Session {
	kid := map[string]interface{}{"kid": p.keys.SigningKeyID()}
	return &systemauth.Session{
		DefaultSession: &openid.DefaultSession{
			Subject: subject,
			Claims: &jwt.IDTokenClaims{
				Issuer:    p.config.Issuer,
				Subject:   subject,
				IssuedAt:  time.Now(),
				ExpiresAt: time.Now().Add(p.config.AccessTokenLifespan),
			},
			Headers: &jwt.Headers{Extra: kid},
		},
		AccessHeader: p.accessTokenHeaders(),
	}
}

// accessTokenHeaders returns the JOSE headers of JWT access tokens.
func (p *Provider) accessTokenHeaders() *jwt.Headers {
	return &jwt.Headers{Extra: map[string]interface{}{"kid": p.keys.SigningKeyID(), "typ": systemauth.AccessTokenType}}
}

// prepareAccessClaims sets the per-issuance claims of JWT access tokens: a
// subject (the client itself for client_credentials), client_id, the cnf
// claim of a DPoP-bound grant, and the at+jwt header with the signing kid.
func (p *Provider) prepareAccessClaims(ar fosite.AccessRequester) error {
	sess, ok := ar.GetSession().(*systemauth.Session)
	if !ok || sess.DefaultSession == nil {
		return fosite.ErrServerError.WithHint("unexpected session type")
	}
	clientID := ar.GetClient().GetID()
	claims := sess.AccessClaims
	if claims == nil {
		claims = &jwt.JWTClaims{}
		sess.AccessClaims = claims
	}
	claims.Subject = sess.GetSubject()
	if claims.Subject == "" {
		claims.Subject = clientID
	}
	claims.IssuedAt = time.Time{}
	claims.NotBefore = time.Time{}
	claims.JTI = ""
	claims.Add("client_id", clientID)
	oauthcore.SetConfirmationClaim(sess.DPoPJKT, claims)
	// A session stored before a key rotation must not keep its old kid.
	sess.AccessHeader = p.accessTokenHeaders()
	return nil
}

// setDPoPNonce adds a fresh server nonce to a token response when nonces
// are on (RFC 9449 §8).
func (p *Provider) setDPoPNonce(w http.ResponseWriter) error {
	nonce, err := p.dpop.Nonce()
	if err != nil {
		return err
	}
	if nonce != "" {
		w.Header().Set("DPoP-Nonce", nonce)
	}
	return nil
}

// introspect validates an access token and returns its request.
func (p *Provider) introspect(ctx context.Context, token string) (fosite.AccessRequester, error) {
	_, ar, err := p.oauth2.IntrospectToken(ctx, token, fosite.AccessToken, p.Session(""))
	return ar, err
}
