// Package jwt provides JWT token generation and validation for SystemForge applications.
package jwt

import (
	"errors"
	"slices"
	"time"
)

// Config holds JWT configuration options.
type Config struct {
	// Secret is the symmetric key used for HS256 signing.
	// Either Secret or PrivateKey must be provided.
	Secret []byte //nolint:gosec // G117: field holds runtime secret value

	// PrivateKey is the RSA or ECDSA private key for RS256/ES256 signing.
	// Either Secret or PrivateKey must be provided.
	PrivateKey any

	// PublicKey is the RSA or ECDSA public key for RS256/ES256 verification.
	// Required when PrivateKey is set.
	PublicKey any

	// Algorithm specifies the signing algorithm.
	// Supported: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
	// Defaults to HS256.
	Algorithm string

	// Issuer is the JWT "iss" claim value.
	Issuer string

	// Audience identifies the application this service issues tokens for
	// (required). Every token the service mints carries it, and
	// ValidateAccessToken and ValidateRefreshToken refuse tokens without it,
	// so a token issued by another application that shares the signing key
	// is not accepted here.
	Audience []string

	// AccessTokenExpiry is the duration before access tokens expire.
	// Defaults to 15 minutes.
	AccessTokenExpiry time.Duration

	// RefreshTokenExpiry is the duration before refresh tokens expire.
	// Defaults to 7 days.
	RefreshTokenExpiry time.Duration

	// RefreshTokenRotation enables automatic refresh token rotation.
	// When enabled, a new refresh token is issued on each refresh.
	RefreshTokenRotation bool
}

// DefaultConfig returns a Config with sensible defaults.
// You must still provide a Secret or PrivateKey.
func DefaultConfig() *Config {
	return &Config{
		Algorithm:            "HS256",
		AccessTokenExpiry:    15 * time.Minute,
		RefreshTokenExpiry:   7 * 24 * time.Hour, // 7 days
		RefreshTokenRotation: true,
	}
}

var (
	// ErrNoSigningKey is returned when no signing key is configured.
	ErrNoSigningKey = errors.New("no signing key configured: provide Secret or PrivateKey")
	// ErrInvalidAlgorithm is returned when an unsupported algorithm is specified.
	ErrInvalidAlgorithm = errors.New("invalid signing algorithm")
	// ErrMissingPublicKey is returned when PrivateKey is set but PublicKey is not.
	ErrMissingPublicKey = errors.New("public key required when using asymmetric signing")
	// ErrMissingAudience is returned when Audience is empty or contains an
	// empty value.
	ErrMissingAudience = errors.New("audience required: set Config.Audience to identify this application")
)

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if len(c.Secret) == 0 && c.PrivateKey == nil {
		return ErrNoSigningKey
	}

	if c.PrivateKey != nil && c.PublicKey == nil {
		return ErrMissingPublicKey
	}

	if len(c.Audience) == 0 || slices.Contains(c.Audience, "") {
		return ErrMissingAudience
	}

	validAlgorithms := map[string]bool{
		"HS256": true, "HS384": true, "HS512": true,
		"RS256": true, "RS384": true, "RS512": true,
		"ES256": true, "ES384": true, "ES512": true,
	}
	if !validAlgorithms[c.Algorithm] {
		return ErrInvalidAlgorithm
	}

	return nil
}
