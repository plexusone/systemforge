// Package jwt provides JWT token generation and validation for SystemForge applications.
package jwt

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Config holds JWT configuration options.
type Config struct {
	// Secret is the symmetric key used for HS256/HS384/HS512 signing. It
	// must be at least as long as the hash output: 32 bytes for HS256, 48
	// for HS384, 64 for HS512. Either Secret or PrivateKey must be provided.
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

	// Issuer is the JWT "iss" claim value (required). Every token carries
	// it and validation rejects tokens from any other issuer.
	Issuer string

	// KeyID is the key identifier ("kid" header) of the signing key
	// (Secret or PrivateKey). When set, every token carries it, and a
	// token's kid selects the verification key: KeyID selects the signing
	// key, a key in VerificationKeys selects that key, and any other kid is
	// rejected. Tokens without a kid are verified with the signing key.
	//
	// Rotation keeps the current key N and the previous key N-1 valid, so
	// any deploy can be rolled back to a configuration that still verifies
	// every outstanding token:
	//
	//  1. Pre-stage: add the new key N to VerificationKeys while N-1 still
	//     signs, and deploy everywhere.
	//  2. Promote: make N the signing key (Secret or PrivateKey and KeyID),
	//     move N-1 into VerificationKeys, and drop N-2. Rolling this deploy
	//     back returns to step 1, which still verifies tokens N signed.
	//
	// Never introduce N and drop N-1 in the same deploy.
	KeyID string

	// VerificationKeys are additional keys, by kid, accepted for
	// verification only: the previous key N-1 and, while it is pre-staged,
	// the next key. Each is an HMAC secret ([]byte) for HS algorithms or a
	// public key for RS and ES algorithms.
	VerificationKeys map[string]any

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
	// ErrMissingIssuer is returned when Issuer is empty.
	ErrMissingIssuer = errors.New("issuer required: set Config.Issuer")
	// ErrWeakSecret is returned when an HMAC secret is shorter than the
	// algorithm's hash output.
	ErrWeakSecret = errors.New("HMAC secret too short for the signing algorithm")
	// ErrInvalidVerificationKey is returned for a VerificationKeys entry
	// that cannot verify tokens of the configured algorithm.
	ErrInvalidVerificationKey = errors.New("invalid verification key")
)

// minHMACSecretLen is the minimum secret length per HMAC algorithm: the
// hash output size (RFC 7518, section 3.2).
var minHMACSecretLen = map[string]int{"HS256": 32, "HS384": 48, "HS512": 64}

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

	if c.Issuer == "" {
		return ErrMissingIssuer
	}

	validAlgorithms := map[string]bool{
		"HS256": true, "HS384": true, "HS512": true,
		"RS256": true, "RS384": true, "RS512": true,
		"ES256": true, "ES384": true, "ES512": true,
	}
	if !validAlgorithms[c.Algorithm] {
		return ErrInvalidAlgorithm
	}

	hmac := strings.HasPrefix(c.Algorithm, "HS")
	if minLen := minHMACSecretLen[c.Algorithm]; hmac && c.PrivateKey == nil && len(c.Secret) < minLen {
		return fmt.Errorf("%w: %s needs at least %d bytes", ErrWeakSecret, c.Algorithm, minLen)
	}

	for kid, key := range c.VerificationKeys {
		if kid == "" || kid == c.KeyID {
			return fmt.Errorf("%w: kid %q must be non-empty and differ from KeyID", ErrInvalidVerificationKey, kid)
		}
		if key == nil {
			return fmt.Errorf("%w: kid %q has no key", ErrInvalidVerificationKey, kid)
		}
		if hmac {
			secret, ok := key.([]byte)
			if !ok {
				return fmt.Errorf("%w: kid %q must be a []byte secret for %s", ErrInvalidVerificationKey, kid, c.Algorithm)
			}
			if minLen := minHMACSecretLen[c.Algorithm]; len(secret) < minLen {
				return fmt.Errorf("%w: kid %q: %w", ErrInvalidVerificationKey, kid, ErrWeakSecret)
			}
		}
	}

	return nil
}
