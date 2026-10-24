package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/grokify/goauth/dpop"
	"github.com/redis/go-redis/v9"

	"github.com/plexusone/systemforge/session/jwt"
)

var (
	// ErrDPoPProofRequired is returned when a DPoP-bound access token
	// (one with a cnf.jkt claim) is presented without a valid DPoP proof,
	// including as a plain Bearer token.
	ErrDPoPProofRequired = errors.New("DPoP-bound token requires the DPoP scheme and a DPoP proof")
	// ErrDPoPTokenNotBound is returned when a token without a cnf.jkt claim
	// is presented with the DPoP scheme.
	ErrDPoPTokenNotBound = errors.New("token presented with the DPoP scheme is not DPoP-bound")
	// ErrDPoPProofReplayed is returned for a proof whose jti was already
	// used.
	ErrDPoPProofReplayed = errors.New("DPoP proof replayed")
	// ErrReplayCacheRequired is returned by NewDPoPAuth without a replay
	// cache.
	ErrReplayCacheRequired = errors.New("DPoPConfig.ReplayCache is required")
)

// ReplayCache records DPoP proof identifiers so that each proof is
// accepted once. Implementations must be safe for concurrent use and, when
// several instances serve the same API, shared between them.
type ReplayCache interface {
	// Use records key until expiresAt and reports whether it was already
	// recorded (a replay).
	Use(ctx context.Context, key string, expiresAt time.Time) (replayed bool, err error)
}

// DPoPConfig configures resource-side DPoP verification (RFC 9449).
type DPoPConfig struct {
	// Verification sets the proof age window and clock skew. Access token
	// binding (the ath claim) is always required. Zero values use
	// dpop.DefaultVerificationConfig.
	Verification dpop.VerificationConfig

	// ReplayCache rejects a proof whose jti has been used before.
	// Required: use NewMemoryReplayCache for a single instance and
	// NewRedisReplayCache when several instances serve the API.
	ReplayCache ReplayCache

	// BaseURL is the scheme and host clients use to reach this API, such as
	// "https://api.example.com"; the proof's htu must equal BaseURL plus the
	// request path. If empty, the scheme comes from the connection (TLS or
	// not) and the host from the Host header. Forwarded headers are never
	// trusted, so set BaseURL behind a proxy that terminates TLS.
	BaseURL string
}

// DPoPAuth validates access tokens and enforces DPoP sender constraint.
type DPoPAuth struct {
	jwt      *jwt.Service
	verifier *dpop.Verifier
	maxAge   time.Duration
	cache    ReplayCache
	baseURL  string
}

// NewDPoPAuth returns DPoP-aware token authentication. A token bound to a
// DPoP key (cnf.jkt) is accepted only with the "DPoP" authorization scheme
// and a proof that is signed by that key, matches the request method and
// URI, carries the hash of the token (ath), is fresh, and has not been
// used before. A token without cnf.jkt is accepted with the "Bearer"
// scheme, as by HTTPAuth.
func NewDPoPAuth(jwtService *jwt.Service, cfg DPoPConfig) (*DPoPAuth, error) {
	if cfg.ReplayCache == nil {
		return nil, ErrReplayCacheRequired
	}
	vc := cfg.Verification
	def := dpop.DefaultVerificationConfig()
	if vc.MaxAge <= 0 {
		vc.MaxAge = def.MaxAge
	}
	if vc.AllowedClockSkew <= 0 {
		vc.AllowedClockSkew = def.AllowedClockSkew
	}
	vc.RequireAccessTokenBinding = true
	return &DPoPAuth{
		jwt:      jwtService,
		verifier: dpop.NewVerifier(vc),
		maxAge:   vc.MaxAge + 2*vc.AllowedClockSkew,
		cache:    cfg.ReplayCache,
		baseURL:  strings.TrimSuffix(cfg.BaseURL, "/"),
	}, nil
}

// Middleware returns middleware that authenticates the request and
// attaches the token's claims to the context, accepting only tokens
// addressed to one of audiences (all of the service's Config.Audience
// when none are given).
func (a *DPoPAuth) Middleware(audiences ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := a.Authenticate(r, audiences...)
			if err != nil {
				w.Header().Set("WWW-Authenticate", `DPoP algs="ES256"`)
				writeUnauthorized(w, err.Error())
				return
			}
			next.ServeHTTP(w, r.WithContext(ContextWithClaims(r.Context(), claims)))
		})
	}
}

// Authenticate validates the request's access token and, for a DPoP-bound
// token, its DPoP proof, and returns the token's claims.
func (a *DPoPAuth) Authenticate(r *http.Request, audiences ...string) (*jwt.Claims, error) {
	scheme, token := extractAuthorization(r)
	if token == "" || (scheme != "bearer" && scheme != "dpop") {
		return nil, errors.New("missing authorization header")
	}

	var claims *jwt.Claims
	var err error
	if len(audiences) > 0 {
		claims, err = a.jwt.ValidateAccessTokenForAudience(token, audiences...)
	} else {
		claims, err = a.jwt.ValidateAccessToken(token)
	}
	if err != nil {
		return nil, err
	}

	if !claims.IsDPoPBound() {
		if scheme == "dpop" {
			return nil, ErrDPoPTokenNotBound
		}
		return claims, nil
	}

	proofs := r.Header.Values(dpop.HeaderDPoP)
	if scheme != "dpop" || len(proofs) != 1 || proofs[0] == "" {
		return nil, ErrDPoPProofRequired
	}
	result, err := a.verifier.Verify(r.Context(), dpop.VerificationRequest{
		Proof:       proofs[0],
		Method:      r.Method,
		URI:         a.requestURI(r),
		AccessToken: token,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDPoPProofRequired, err)
	}
	if err := dpop.VerifyTokenBinding(claims.DPoPThumbprint(), result.Thumbprint); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDPoPProofRequired, err)
	}
	replayed, err := a.cache.Use(r.Context(), result.Thumbprint+":"+result.JTI, result.IssuedAt.Add(a.maxAge))
	if err != nil {
		return nil, fmt.Errorf("checking DPoP proof replay: %w", err)
	}
	if replayed {
		return nil, ErrDPoPProofReplayed
	}
	return claims, nil
}

// requestURI is the htu a proof for r must carry.
func (a *DPoPAuth) requestURI(r *http.Request) string {
	if a.baseURL != "" {
		return a.baseURL + r.URL.Path
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

// HTTPAuthDPoP is HTTPAuth with DPoP enforcement; see NewDPoPAuth.
func HTTPAuthDPoP(jwtService *jwt.Service, cfg DPoPConfig) (func(http.Handler) http.Handler, error) {
	a, err := NewDPoPAuth(jwtService, cfg)
	if err != nil {
		return nil, err
	}
	return a.Middleware(), nil
}

// extractAuthorization returns the lower-cased scheme and the credentials
// of the Authorization header.
func extractAuthorization(r *http.Request) (scheme, token string) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok {
		return "", ""
	}
	return strings.ToLower(scheme), strings.TrimSpace(token)
}

// MemoryReplayCache is an in-process ReplayCache, suitable when one
// instance serves the API.
type MemoryReplayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
	lastGC  time.Time
}

// NewMemoryReplayCache returns an empty in-process replay cache.
func NewMemoryReplayCache() *MemoryReplayCache {
	return &MemoryReplayCache{entries: make(map[string]time.Time)}
}

// Use implements ReplayCache.
func (c *MemoryReplayCache) Use(_ context.Context, key string, expiresAt time.Time) (bool, error) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if now.Sub(c.lastGC) > time.Minute {
		for k, exp := range c.entries {
			if now.After(exp) {
				delete(c.entries, k)
			}
		}
		c.lastGC = now
	}
	if exp, ok := c.entries[key]; ok && !now.After(exp) {
		return true, nil
	}
	c.entries[key] = expiresAt
	return false, nil
}

// RedisReplayCache is a ReplayCache shared through Redis, for APIs served
// by several instances.
type RedisReplayCache struct {
	client redis.UniversalClient
	prefix string
}

// NewRedisReplayCache returns a replay cache that stores keys in Redis
// under prefix (for example "dpop-jti:").
func NewRedisReplayCache(client redis.UniversalClient, prefix string) *RedisReplayCache {
	return &RedisReplayCache{client: client, prefix: prefix}
}

// Use implements ReplayCache with SET NX and an expiry.
func (c *RedisReplayCache) Use(ctx context.Context, key string, expiresAt time.Time) (bool, error) {
	ttl := time.Until(expiresAt)
	if ttl < time.Second {
		ttl = time.Second
	}
	stored, err := c.client.SetNX(ctx, c.prefix+key, 1, ttl).Result()
	if err != nil {
		return false, err
	}
	return !stored, nil
}
