package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Service provides JWT token operations.
type Service struct {
	config *Config
}

// NewService creates a new JWT service with the given configuration.
func NewService(cfg *Config) (*Service, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid jwt config: %w", err)
	}

	return &Service{config: cfg}, nil
}

var (
	// ErrInvalidToken is returned when a token cannot be parsed or validated.
	ErrInvalidToken = errors.New("invalid token")
	// ErrTokenExpired is returned when a token has expired.
	ErrTokenExpired = errors.New("token expired")
	// ErrWrongTokenType is returned when the token type doesn't match expectations.
	ErrWrongTokenType = errors.New("wrong token type")
	// ErrAudienceMismatch is returned when the token is not addressed to the
	// expected audience: this application's Config.Audience, or the
	// audiences a caller asked for.
	ErrAudienceMismatch = errors.New("audience mismatch")
	// ErrScopesRequired is returned when API tokens are created without scopes.
	ErrScopesRequired = errors.New("at least one scope is required for API tokens")
)

// Audience constants for different token types.
const (
	// AudienceBFF is the audience for BFF (web browser) clients.
	// These tokens are used for cookie-based sessions.
	AudienceBFF = "bff"
	// AudienceAPI is the audience for programmatic API clients.
	// These tokens are used with Bearer authentication and require scopes.
	AudienceAPI = "api"
)

// GenerateAccessToken creates a new access token for the given principal.
func (s *Service) GenerateAccessToken(principalID uuid.UUID, email, name string) (string, error) {
	claims := NewAccessClaims(s.config, principalID, email, name)
	return s.signToken(claims)
}

// TokenOptions contains optional parameters for token generation.
type TokenOptions struct {
	// DPoPThumbprint binds the token to a DPoP key pair.
	// When set, the token will include a cnf.jkt claim.
	DPoPThumbprint string

	// Audience replaces the configured audience on this token, for example to
	// address it to one application when several share a signing key. Such
	// a token is accepted only by ValidateAccessTokenForAudience (or a
	// service whose Config.Audience includes one of these values).
	Audience []string
}

func (o TokenOptions) apply(c *Claims) {
	if o.DPoPThumbprint != "" {
		c.WithDPoPBinding(o.DPoPThumbprint)
	}
	if len(o.Audience) > 0 {
		c.WithAudience(o.Audience...)
	}
}

// GenerateAccessTokenWithOptions creates a new access token with optional parameters.
func (s *Service) GenerateAccessTokenWithOptions(principalID uuid.UUID, email, name string, opts TokenOptions) (string, error) {
	claims := NewAccessClaims(s.config, principalID, email, name)
	opts.apply(claims)
	return s.signToken(claims)
}

// GenerateAccessTokenWithOrg creates an access token with organization context.
func (s *Service) GenerateAccessTokenWithOrg(
	principalID uuid.UUID,
	email, name string,
	orgID uuid.UUID,
	orgSlug, role string,
	permissions []string,
	isPlatformAdmin bool,
) (string, error) {
	claims := NewAccessClaims(s.config, principalID, email, name).
		WithOrganization(orgID, orgSlug, role, permissions).
		WithPlatformAdmin(isPlatformAdmin)
	return s.signToken(claims)
}

// GenerateAccessTokenWithOrgAndOptions creates an access token with organization context and options.
func (s *Service) GenerateAccessTokenWithOrgAndOptions(
	principalID uuid.UUID,
	email, name string,
	orgID uuid.UUID,
	orgSlug, role string,
	permissions []string,
	isPlatformAdmin bool,
	opts TokenOptions,
) (string, error) {
	claims := NewAccessClaims(s.config, principalID, email, name).
		WithOrganization(orgID, orgSlug, role, permissions).
		WithPlatformAdmin(isPlatformAdmin)
	opts.apply(claims)
	return s.signToken(claims)
}

// GenerateRefreshToken creates a new refresh token for the given principal.
// The family parameter is used for refresh token rotation tracking.
func (s *Service) GenerateRefreshToken(principalID uuid.UUID, family string) (string, error) {
	if family == "" {
		family = uuid.NewString()
	}
	claims := NewRefreshClaims(s.config, principalID, family)
	return s.signToken(claims)
}

// TokenPair represents an access token and refresh token pair.
//
//nolint:gosec // G117: struct fields hold runtime OAuth tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // Access token expiry in seconds
}

// GenerateTokenPair creates both an access token and refresh token.
func (s *Service) GenerateTokenPair(principalID uuid.UUID, email, name string) (*TokenPair, error) {
	accessToken, err := s.GenerateAccessToken(principalID, email, name)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	family := uuid.NewString()
	refreshToken, err := s.GenerateRefreshToken(principalID, family)
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.AccessTokenExpiry.Seconds()),
	}, nil
}

// GenerateTokenPairWithOptions creates a token pair with optional DPoP binding.
func (s *Service) GenerateTokenPairWithOptions(principalID uuid.UUID, email, name string, opts TokenOptions) (*TokenPair, error) {
	accessToken, err := s.GenerateAccessTokenWithOptions(principalID, email, name, opts)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	family := uuid.NewString()
	refreshToken, err := s.GenerateRefreshToken(principalID, family)
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.AccessTokenExpiry.Seconds()),
	}, nil
}

// GenerateTokenPairWithOrg creates a token pair with organization context.
func (s *Service) GenerateTokenPairWithOrg(
	principalID uuid.UUID,
	email, name string,
	orgID uuid.UUID,
	orgSlug, role string,
	permissions []string,
	isPlatformAdmin bool,
) (*TokenPair, error) {
	accessToken, err := s.GenerateAccessTokenWithOrg(
		principalID, email, name, orgID, orgSlug, role, permissions, isPlatformAdmin,
	)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	family := uuid.NewString()
	refreshToken, err := s.GenerateRefreshToken(principalID, family)
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.AccessTokenExpiry.Seconds()),
	}, nil
}

// ValidateAccessToken validates and parses an access token addressed to
// this application: its audience must include one of Config.Audience.
func (s *Service) ValidateAccessToken(tokenString string) (*Claims, error) {
	return s.validateAccess(tokenString, s.config.Audience)
}

// ValidateAccessTokenForAudience is ValidateAccessToken for a verifier
// that serves one kind of client or one application: the token must be
// addressed to one of the audiences (AudienceBFF, AudienceAPI, or an
// application's own), which replace Config.Audience for this check. A
// token minted for another audience, for example a narrowly scoped API
// token, is refused with ErrAudienceMismatch rather than accepted as a
// full session. With no audiences every token is refused.
func (s *Service) ValidateAccessTokenForAudience(tokenString string, audiences ...string) (*Claims, error) {
	return s.validateAccess(tokenString, audiences)
}

func (s *Service) validateAccess(tokenString string, audiences []string) (*Claims, error) {
	claims, err := s.parseToken(tokenString)
	if err != nil {
		return nil, err
	}
	if !claims.IsAccessToken() {
		return nil, ErrWrongTokenType
	}
	if !claims.HasAnyAudience(audiences...) {
		return nil, ErrAudienceMismatch
	}
	return claims, nil
}

// ValidateRefreshToken validates and parses a refresh token.
func (s *Service) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := s.parseToken(tokenString)
	if err != nil {
		return nil, err
	}

	if !claims.IsRefreshToken() {
		return nil, ErrWrongTokenType
	}

	// A refresh token from another application sharing the signing key
	// must not mint tokens here.
	if !claims.HasAnyAudience(s.config.Audience...) {
		return nil, ErrAudienceMismatch
	}

	return claims, nil
}

// ValidateAccessTokenWithAudience validates an access token addressed to
// expectedAudience. An empty expectedAudience checks Config.Audience, as
// ValidateAccessToken does.
func (s *Service) ValidateAccessTokenWithAudience(tokenString string, expectedAudience string) (*Claims, error) {
	if expectedAudience == "" {
		return s.ValidateAccessToken(tokenString)
	}
	return s.validateAccess(tokenString, []string{expectedAudience})
}

// GenerateAccessTokenWithAudience creates an access token for a kind of
// client: its audience is the given value followed by Config.Audience.
func (s *Service) GenerateAccessTokenWithAudience(
	principalID uuid.UUID,
	email, name string,
	audience string,
	scopes []string,
) (string, error) {
	claims := NewAccessClaims(s.config, principalID, email, name).
		withKind(audience)

	if len(scopes) > 0 {
		claims.Scopes = scopes
	}

	return s.signToken(claims)
}

// GenerateBFFTokenPair creates a token pair for BFF (web) clients.
// BFF tokens use cookie-based sessions and don't include scopes.
func (s *Service) GenerateBFFTokenPair(principalID uuid.UUID, email, name string) (*TokenPair, error) {
	return s.GenerateTokenPairWithAudience(principalID, email, name, AudienceBFF, nil)
}

// GenerateAPIToken creates a scoped token for API clients.
// API tokens require at least one scope.
// Duration overrides the default access token expiry if positive.
func (s *Service) GenerateAPIToken(
	principalID uuid.UUID,
	email, name string,
	scopes []string,
	duration time.Duration,
) (string, error) {
	if len(scopes) == 0 {
		return "", ErrScopesRequired
	}

	claims := NewAccessClaims(s.config, principalID, email, name).
		withKind(AudienceAPI)
	claims.Scopes = scopes

	// Override expiry if duration provided
	if duration > 0 {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(duration))
	}

	return s.signToken(claims)
}

// GenerateTokenPairWithAudience creates a token pair with explicit audience.
func (s *Service) GenerateTokenPairWithAudience(
	principalID uuid.UUID,
	email, name string,
	audience string,
	scopes []string,
) (*TokenPair, error) {
	accessToken, err := s.GenerateAccessTokenWithAudience(principalID, email, name, audience, scopes)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	family := uuid.NewString()
	refreshToken, err := s.GenerateRefreshToken(principalID, family)
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.AccessTokenExpiry.Seconds()),
	}, nil
}

// signToken creates a signed JWT from the given claims.
func (s *Service) signToken(claims *Claims) (string, error) {
	var method jwt.SigningMethod
	switch s.config.Algorithm {
	case "HS256":
		method = jwt.SigningMethodHS256
	case "HS384":
		method = jwt.SigningMethodHS384
	case "HS512":
		method = jwt.SigningMethodHS512
	case "RS256":
		method = jwt.SigningMethodRS256
	case "RS384":
		method = jwt.SigningMethodRS384
	case "RS512":
		method = jwt.SigningMethodRS512
	case "ES256":
		method = jwt.SigningMethodES256
	case "ES384":
		method = jwt.SigningMethodES384
	case "ES512":
		method = jwt.SigningMethodES512
	default:
		method = jwt.SigningMethodHS256
	}

	token := jwt.NewWithClaims(method, claims)

	var key any
	if s.config.PrivateKey != nil {
		key = s.config.PrivateKey
	} else {
		key = s.config.Secret
	}

	return token.SignedString(key)
}

// parseToken parses and validates a JWT token string.
func (s *Service) parseToken(tokenString string) (*Claims, error) {
	keyFunc := func(token *jwt.Token) (any, error) {
		// Verify signing method matches configuration
		switch s.config.Algorithm {
		case "HS256", "HS384", "HS512":
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.config.Secret, nil
		case "RS256", "RS384", "RS512":
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.config.PublicKey, nil
		case "ES256", "ES384", "ES512":
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.config.PublicKey, nil
		default:
			return nil, ErrInvalidAlgorithm
		}
	}

	// Pin the algorithm, and require an expiry so a token minted without
	// one never becomes immortal. The issuer is checked when configured.
	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{s.config.Algorithm}),
		jwt.WithExpirationRequired(),
	}
	if s.config.Issuer != "" {
		parserOpts = append(parserOpts, jwt.WithIssuer(s.config.Issuer))
	}
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc, parserOpts...)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// Config returns the service configuration.
func (s *Service) Config() *Config {
	return s.config
}

// RefreshTokenTTL returns the refresh token expiry duration.
// This method provides compatibility with goauth/jwt.Service.
func (s *Service) RefreshTokenTTL() time.Duration {
	return s.config.RefreshTokenExpiry
}

// AccessTokenTTL returns the access token expiry duration.
// This method provides compatibility with goauth/jwt.Service.
func (s *Service) AccessTokenTTL() time.Duration {
	return s.config.AccessTokenExpiry
}

// GenerateTokenPairLegacy creates a token pair using the legacy goauth interface.
// This provides backward compatibility during migration from goauth/jwt.
// Deprecated: Use GenerateTokenPair or GenerateTokenPairWithOrg instead.
func (s *Service) GenerateTokenPairLegacy(principalID uuid.UUID, email string, isPlatformAdmin bool) (*TokenPair, error) {
	// Use isPlatformAdmin to determine name fallback
	name := email // Use email as name fallback

	accessToken, err := s.GenerateAccessTokenWithOrg(
		principalID, email, name,
		uuid.Nil, "", "", nil, isPlatformAdmin,
	)
	if err != nil {
		return nil, fmt.Errorf("generating access token: %w", err)
	}

	family := uuid.NewString()
	refreshToken, err := s.GenerateRefreshToken(principalID, family)
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.config.AccessTokenExpiry.Seconds()),
	}, nil
}
