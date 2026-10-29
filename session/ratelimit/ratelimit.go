// Package ratelimit provides HTTP rate limiting middleware with support for
// per-principal and per-application rate limits.
//
// The package supports multiple storage backends (in-memory, Redis) and
// integrates with Cedar policies for dynamic tier-based rate limiting.
package ratelimit

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/plexusone/systemforge/observability"
)

// Common errors returned by the rate limiter.
var (
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	ErrStorageFailure    = errors.New("rate limit storage failure")
)

// Limit defines rate limit parameters.
type Limit struct {
	// Rate is the number of requests allowed per Period.
	Rate int

	// Period is the time window for the rate limit (e.g., time.Minute).
	Period time.Duration

	// Burst is the maximum number of requests allowed in a single burst.
	// If zero, defaults to Rate.
	Burst int
}

// DefaultLimit returns a sensible default rate limit (100 requests per minute).
func DefaultLimit() Limit {
	return Limit{
		Rate:   100,
		Period: time.Minute,
		Burst:  100,
	}
}

// PerSecond creates a rate limit of n requests per second.
func PerSecond(n int) Limit {
	return Limit{Rate: n, Period: time.Second, Burst: n}
}

// PerMinute creates a rate limit of n requests per minute.
func PerMinute(n int) Limit {
	return Limit{Rate: n, Period: time.Minute, Burst: n}
}

// PerHour creates a rate limit of n requests per hour.
func PerHour(n int) Limit {
	return Limit{Rate: n, Period: time.Hour, Burst: n}
}

// Result contains the outcome of a rate limit check.
type Result struct {
	// Allowed is true if the request should be permitted.
	Allowed bool

	// Remaining is the number of requests remaining in the current window.
	Remaining int

	// ResetAt is when the rate limit window resets.
	ResetAt time.Time

	// RetryAfter is the duration to wait before retrying (only set if not allowed).
	RetryAfter time.Duration
}

// Storage defines the interface for rate limit state storage.
type Storage interface {
	// Allow checks if a request should be allowed and updates the counter.
	// Returns the result of the check and any error.
	Allow(ctx context.Context, key string, limit Limit) (Result, error)

	// Reset clears the rate limit state for a key.
	Reset(ctx context.Context, key string) error

	// Close releases any resources held by the storage.
	Close() error
}

// LimitResolver determines the rate limit for a given request.
// This allows dynamic rate limiting based on user tier, endpoint, etc.
type LimitResolver interface {
	// Resolve returns the rate limit for the given key and context.
	// The key is typically derived from the principal ID or client ID.
	Resolve(ctx context.Context, key string, r *http.Request) Limit
}

// StaticResolver always returns the same limit.
type StaticResolver struct {
	Limit Limit
}

// Resolve implements LimitResolver.
func (s *StaticResolver) Resolve(ctx context.Context, key string, r *http.Request) Limit {
	return s.Limit
}

// TieredResolver returns different limits based on tier.
type TieredResolver struct {
	Tiers    map[string]Limit
	Default  Limit
	TierFunc func(ctx context.Context, key string, r *http.Request) string
	mu       sync.RWMutex
}

// Resolve implements LimitResolver.
func (t *TieredResolver) Resolve(ctx context.Context, key string, r *http.Request) Limit {
	tier := "default"
	if t.TierFunc != nil {
		tier = t.TierFunc(ctx, key, r)
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if limit, ok := t.Tiers[tier]; ok {
		return limit
	}
	return t.Default
}

// KeyFunc extracts the rate limit key from a request.
// Common implementations include extracting principal ID or client ID from JWT.
type KeyFunc func(r *http.Request) string

// Limiter is the main rate limiter type.
type Limiter struct {
	storage       Storage
	resolver      LimitResolver
	keyFunc       KeyFunc
	observability *observability.Observability
	failOpen      bool
	logger        *slog.Logger
	name          string
	skip          func(r *http.Request) bool
}

// New creates a new Limiter with the given storage and options.
func New(storage Storage, opts ...Option) *Limiter {
	l := &Limiter{
		storage:  storage,
		resolver: &StaticResolver{Limit: DefaultLimit()},
		keyFunc:  IPKey(),
		logger:   slog.Default(),
		name:     DefaultPolicyName,
	}

	for _, opt := range opts {
		opt(l)
	}

	return l
}

// Option configures a Limiter.
type Option func(*Limiter)

// WithResolver sets a custom limit resolver.
func WithResolver(resolver LimitResolver) Option {
	return func(l *Limiter) {
		l.resolver = resolver
	}
}

// WithLimit sets a static rate limit.
func WithLimit(limit Limit) Option {
	return func(l *Limiter) {
		l.resolver = &StaticResolver{Limit: limit}
	}
}

// WithKeyFunc sets the function to extract rate limit keys from requests.
func WithKeyFunc(keyFunc KeyFunc) Option {
	return func(l *Limiter) {
		l.keyFunc = keyFunc
	}
}

// WithFailOpen lets requests through when the storage fails. By default
// the middleware fails closed, answering 503, because a storage outage
// otherwise switches off the limits that protect authentication endpoints
// at the moment an attacker may be causing it.
func WithFailOpen() Option {
	return func(l *Limiter) {
		l.failOpen = true
	}
}

// WithName names the limit: the policy name in the RateLimit-Policy and
// RateLimit headers and in metrics. Default: DefaultPolicyName.
func WithName(name string) Option {
	return func(l *Limiter) {
		if name != "" {
			l.name = name
		}
	}
}

// WithSkip exempts the requests skip reports true for, such as anonymous
// requests to a limit keyed by the signed-in principal.
func WithSkip(skip func(r *http.Request) bool) Option {
	return func(l *Limiter) {
		l.skip = skip
	}
}

// WithLogger sets the logger for storage failures.
func WithLogger(logger *slog.Logger) Option {
	return func(l *Limiter) {
		l.logger = logger
	}
}

// WithObservability sets the observability provider for metrics and tracing.
func WithObservability(obs *observability.Observability) Option {
	return func(l *Limiter) {
		l.observability = obs
	}
}

// Allow checks if a request should be allowed.
func (l *Limiter) Allow(r *http.Request) (Result, error) {
	ctx := r.Context()
	key := l.keyFunc(r)
	limit := l.resolver.Resolve(ctx, key, r)
	return l.storage.Allow(ctx, key, limit)
}

// Middleware returns an HTTP middleware that enforces rate limits. Every
// checked response carries the RateLimit-Policy, RateLimit and
// X-RateLimit-* headers; a refused one is a 429 with Retry-After of at
// least one second. A storage failure answers 503 unless WithFailOpen is
// given, and a full MemoryStorage (ErrTooManyKeys) is always a 429.
func (l *Limiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l.skip != nil && l.skip(r) {
				next.ServeHTTP(w, r)
				return
			}
			ctx := r.Context()
			key := l.keyFunc(r)
			limit := l.resolver.Resolve(ctx, key, r)

			result, err := l.storage.Allow(ctx, key, limit)
			if errors.Is(err, ErrTooManyKeys) {
				l.logger.WarnContext(ctx, "rate limit storage is full", "policy", l.name)
				WriteTooManyRequests(w, tooManyKeysWait)
				return
			}
			if err != nil {
				l.logger.ErrorContext(ctx, "rate limit storage failed", "policy", l.name, "error", err, "fail_open", l.failOpen)
				if l.failOpen {
					next.ServeHTTP(w, r)
					return
				}
				writeUnavailable(w)
				return
			}

			// Record rate limit metrics
			if l.observability != nil {
				l.observability.RecordRateLimitRequest(ctx, l.name, key, result.Allowed)
				// Calculate usage ratio
				if limit.Rate > 0 {
					usage := float64(limit.Rate-result.Remaining) / float64(limit.Rate)
					l.observability.RecordRateLimitUsage(ctx, l.name, key, limit.Period.String(), usage)
				}
			}

			WriteHeaders(w.Header(), l.name, limit, result)
			if !result.Allowed {
				WriteTooManyRequests(w, result.RetryAfter)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Close releases resources held by the limiter.
func (l *Limiter) Close() error {
	return l.storage.Close()
}
