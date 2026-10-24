// Package dpopproof verifies DPoP proofs (RFC 9449) for servers that issue
// or accept DPoP-bound tokens, and yields a Proof only for a proof that
// passed every check, so a token is bound only to a key its client proved
// it holds.
//
// A Checker verifies the proof's signature and typ, that its htm and htu
// match the request, that it is fresh (iat), that its jti has not been seen
// before (ReplayCache), that it carries the hash of the access token when
// one is presented (ath), and, when server nonces are on, that it carries a
// nonce this server issued recently.
package dpopproof

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/grokify/goauth/dpop"
)

// Algorithms are the JWS algorithms accepted for proofs, as advertised in
// dpop_signing_alg_values_supported.
var Algorithms = []string{"ES256", "ES384", "ES512"}

var (
	// ErrMissing is returned when a request carries no DPoP proof.
	ErrMissing = errors.New("dpopproof: DPoP proof required")
	// ErrInvalid is returned for a proof that fails verification, or for a
	// request with more than one DPoP header.
	ErrInvalid = errors.New("dpopproof: invalid DPoP proof")
	// ErrReplayed is returned for a proof whose jti was already used.
	ErrReplayed = fmt.Errorf("%w: replayed", ErrInvalid)
	// ErrUseNonce is returned when server nonces are on and the proof
	// carries no nonce, or one this server did not issue recently. The
	// client should retry with the nonce in the DPoP-Nonce response header.
	ErrUseNonce = errors.New("dpopproof: DPoP proof must carry a fresh server nonce")
	// ErrReplayCacheRequired is returned by NewChecker without a replay
	// cache.
	ErrReplayCacheRequired = errors.New("dpopproof: Config.ReplayCache is required")
)

// ReplayCache records proof identifiers so each proof is accepted once.
// Implementations must be safe for concurrent use and shared between the
// instances that accept proofs for the same URIs. The caches in
// session/middleware (NewMemoryReplayCache, NewRedisReplayCache) implement
// it.
type ReplayCache interface {
	// Use records key until expiresAt and reports whether it was already
	// recorded (a replay).
	Use(ctx context.Context, key string, expiresAt time.Time) (replayed bool, err error)
}

// Config configures a Checker.
type Config struct {
	// MaxAge is how old a proof's iat may be. Default: 5 minutes.
	MaxAge time.Duration

	// ClockSkew is how far a proof's iat may be in the future, and is added
	// to MaxAge. Default: 30 seconds.
	ClockSkew time.Duration

	// ReplayCache rejects a proof whose jti was used before (required).
	ReplayCache ReplayCache

	// Nonces, when set, requires every proof to carry a nonce it issued
	// (RFC 9449 §8), which bounds how long a proof made ahead of time is
	// usable whatever its iat says.
	Nonces *Nonces
}

// Checker verifies DPoP proofs.
type Checker struct {
	verifier *dpop.Verifier
	keep     time.Duration
	cache    ReplayCache
	nonces   *Nonces
}

// NewChecker returns a Checker for cfg.
func NewChecker(cfg Config) (*Checker, error) {
	if cfg.ReplayCache == nil {
		return nil, ErrReplayCacheRequired
	}
	def := dpop.DefaultVerificationConfig()
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = def.MaxAge
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = def.AllowedClockSkew
	}
	vc := dpop.VerificationConfig{MaxAge: cfg.MaxAge, AllowedClockSkew: cfg.ClockSkew}
	if cfg.Nonces != nil {
		vc.NonceValidator = cfg.Nonces.validate
	}
	return &Checker{
		verifier: dpop.NewVerifier(vc),
		keep:     cfg.MaxAge + 2*cfg.ClockSkew,
		cache:    cfg.ReplayCache,
		nonces:   cfg.Nonces,
	}, nil
}

// Proof is a verified DPoP proof. Only a Checker creates one, so a Proof
// is evidence that the request's sender holds the private key whose
// thumbprint JKT returns.
type Proof struct {
	jkt string
	jti string
	iat time.Time
}

// JKT returns the RFC 7638 SHA-256 thumbprint of the proof's key, the
// value of a bound token's cnf.jkt claim; "" for a nil Proof (no proof).
func (p *Proof) JKT() string {
	if p == nil {
		return ""
	}
	return p.jkt
}

// JTI returns the proof's unique identifier.
func (p *Proof) JTI() string { return p.jti }

// IssuedAt returns the proof's iat.
func (p *Proof) IssuedAt() time.Time { return p.iat }

// Target is what a proof must be made for.
type Target struct {
	// Method is the request method the proof's htm must name.
	Method string
	// URI is the request URI without query or fragment the proof's htu
	// must name. Behind a proxy that terminates TLS, build it from the
	// configured external base URL rather than the request.
	URI string
	// AccessToken, when set, is the token presented with the proof, whose
	// hash the proof's ath must carry.
	AccessToken string //nolint:gosec // G117: field holds a runtime token value
}

// Proofs returns the DPoP header values of r.
func Proofs(r *http.Request) []string {
	return r.Header.Values(dpop.HeaderDPoP)
}

// Present reports whether r carries a DPoP header.
func Present(r *http.Request) bool {
	return len(Proofs(r)) > 0
}

// Check verifies the DPoP proof of r for target. It returns ErrMissing
// when r carries none; ErrInvalid (or ErrReplayed) for a bad proof or more
// than one DPoP header; ErrUseNonce when a server nonce is required. Other
// errors come from the replay cache.
func (c *Checker) Check(ctx context.Context, r *http.Request, target Target) (*Proof, error) {
	proofs := Proofs(r)
	switch {
	case len(proofs) == 0:
		return nil, ErrMissing
	case len(proofs) > 1:
		return nil, fmt.Errorf("%w: more than one DPoP header", ErrInvalid)
	case proofs[0] == "":
		return nil, ErrMissing
	}
	return c.Verify(ctx, proofs[0], target)
}

// Verify verifies one DPoP proof for target; see Check.
func (c *Checker) Verify(ctx context.Context, proof string, target Target) (*Proof, error) {
	req := dpop.VerificationRequest{Proof: proof, Method: target.Method, URI: target.URI}
	if err := checkHeader(proof); err != nil {
		return nil, err
	}
	if target.AccessToken != "" {
		parsed, err := dpop.ParseProof(proof)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		// The library checks ath only when the proof carries one; a
		// proof presented with a token must.
		if parsed.Claims.AccessTokenHash == "" {
			return nil, fmt.Errorf("%w: the proof carries no ath for the access token", ErrInvalid)
		}
		req.AccessToken = target.AccessToken
	}
	result, err := c.verifier.Verify(ctx, req)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		if errors.Is(err, dpop.ErrNonceMismatch) {
			return nil, ErrUseNonce
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	replayed, err := c.cache.Use(ctx, result.Thumbprint+":"+result.JTI, result.IssuedAt.Add(c.keep))
	if err != nil {
		return nil, fmt.Errorf("dpopproof: checking proof replay: %w", err)
	}
	if replayed {
		return nil, ErrReplayed
	}
	return &Proof{jkt: result.Thumbprint, jti: result.JTI, iat: result.IssuedAt}, nil
}

// checkHeader refuses a proof whose jwk header carries a private key
// (RFC 9449 §4.3), which the proof library does not look at.
func checkHeader(proof string) error {
	head, _, ok := strings.Cut(proof, ".")
	if !ok {
		return fmt.Errorf("%w: not a JWT", ErrInvalid)
	}
	raw, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return fmt.Errorf("%w: header encoding: %v", ErrInvalid, err)
	}
	var header struct {
		JWK map[string]any `json:"jwk"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return fmt.Errorf("%w: header: %v", ErrInvalid, err)
	}
	if _, private := header.JWK["d"]; private {
		return fmt.Errorf("%w: the jwk header carries a private key", ErrInvalid)
	}
	return nil
}

// Nonce returns a fresh server nonce for the DPoP-Nonce response header,
// or "" when server nonces are off.
func (c *Checker) Nonce() (string, error) {
	if c.nonces == nil {
		return "", nil
	}
	return c.nonces.Issue()
}

// NoncesRequired reports whether proofs must carry a server nonce.
func (c *Checker) NoncesRequired() bool { return c.nonces != nil }
