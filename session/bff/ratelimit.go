package bff

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
)

// RateLimitConfig contains configuration for rate limiting.
type RateLimitConfig struct {
	// RequestsPerMinute is the sustained request rate.
	// Default: 60.
	RequestsPerMinute int

	// BurstSize is the maximum burst of requests allowed.
	// Default: 10.
	BurstSize int

	// EndpointLimits allows per-endpoint rate limit overrides.
	// Key is the endpoint path relative to where the BFF router is
	// mounted (e.g., "/refresh", "/logout"); see BasePath. Each endpoint
	// listed here has its own bucket per client, separate from the
	// default bucket shared by all other paths.
	EndpointLimits map[string]EndpointLimit

	// KeyFunc extracts the rate limit key from a request.
	// Default: client IP address.
	KeyFunc func(r *http.Request) string

	// OnLimitExceeded is called when rate limit is exceeded.
	// If nil, returns 429 Too Many Requests with standard headers.
	OnLimitExceeded func(w http.ResponseWriter, r *http.Request, info RateLimitInfo)

	// ExcludePaths are paths that bypass rate limiting, matched like
	// EndpointLimits keys.
	// Example: []string{"/health", "/metrics"}
	ExcludePaths []string

	// BasePath is stripped from the request path before EndpointLimits and
	// ExcludePaths are matched, for routers that do not strip the mount
	// prefix themselves. When the limiter runs inside a chi router mounted
	// with Mount (as Handler.Router is), the path relative to the mount
	// point is used automatically and BasePath is not needed.
	BasePath string

	// ClientIPConfig configures client address extraction for the default
	// key. NewHandler fills it from HandlerConfig.ClientIPConfig when it is
	// left zero. The default keys on the direct peer.
	ClientIPConfig ClientIPConfig

	// TrustCloudflare uses CF-Connecting-IP for client identification.
	//
	// Deprecated: set ClientIPConfig with CloudflareIPRanges. Without
	// ranges proving the request came through Cloudflare the header is
	// ignored, because any client can send it.
	TrustCloudflare bool

	// CleanupInterval is how often to clean up expired entries.
	// Default: 1 minute.
	CleanupInterval time.Duration
}

// EndpointLimit defines rate limits for a specific endpoint.
type EndpointLimit struct {
	RequestsPerMinute int
	BurstSize         int
}

// RateLimitInfo contains information about the current rate limit state.
type RateLimitInfo struct {
	Limit      int       // Maximum requests per window
	Remaining  int       // Requests remaining in current window
	ResetAt    time.Time // When the window resets
	RetryAfter int       // Seconds until next request allowed (if limited)
}

// DefaultRateLimitConfig returns sensible default rate limit configuration.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerMinute: 60,
		BurstSize:         10,
		CleanupInterval:   time.Minute,
	}
}

// RateLimiter implements token bucket rate limiting.
type RateLimiter struct {
	config       RateLimitConfig
	buckets      map[string]*tokenBucket
	mu           sync.RWMutex
	ipExtractor  *ClientIPExtractor
	excludePaths map[string]bool
	stopCleanup  chan struct{}
}

// tokenBucket implements the token bucket algorithm.
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	if config.RequestsPerMinute <= 0 {
		config.RequestsPerMinute = 60
	}
	if config.BurstSize <= 0 {
		config.BurstSize = 10
	}
	if config.CleanupInterval <= 0 {
		config.CleanupInterval = time.Minute
	}

	// Build exclude paths map
	excludePaths := make(map[string]bool)
	for _, path := range config.ExcludePaths {
		excludePaths[path] = true
	}

	// Create IP extractor
	ipConfig := config.ClientIPConfig
	if config.TrustCloudflare {
		ipConfig.TrustCloudflare = true
	}

	rl := &RateLimiter{
		config:       config,
		buckets:      make(map[string]*tokenBucket),
		ipExtractor:  NewClientIPExtractor(ipConfig),
		excludePaths: excludePaths,
		stopCleanup:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// Middleware returns HTTP middleware that enforces rate limits.
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := rl.routePath(r)

			// Check if path is excluded
			if rl.excludePaths[path] {
				next.ServeHTTP(w, r)
				return
			}

			// Get limits for this endpoint. An endpoint with its own
			// limits gets its own bucket, so traffic to other paths cannot
			// fix its capacity and it cannot drain theirs.
			limit, burst, class := rl.getLimits(path)
			key := class + "\x00" + rl.getKey(r)

			// Check rate limit
			info, allowed := rl.allow(key, limit, burst)

			// Set rate limit headers
			rl.setHeaders(w, info)

			if !allowed {
				rl.handleLimitExceeded(w, r, info)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getKey extracts the rate limit key from the request.
func (rl *RateLimiter) getKey(r *http.Request) string {
	if rl.config.KeyFunc != nil {
		return rl.config.KeyFunc(r)
	}
	return rl.ipExtractor.GetClientIP(r)
}

// routePath returns the request path relative to the router the limiter is
// mounted in: chi's remaining route path when mounted with chi, otherwise
// the URL path with BasePath removed.
func (rl *RateLimiter) routePath(r *http.Request) string {
	if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePath != "" {
		return rctx.RoutePath
	}
	path := r.URL.Path
	if rl.config.BasePath != "" {
		if rest, ok := strings.CutPrefix(path, strings.TrimSuffix(rl.config.BasePath, "/")); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
			path = rest
			if path == "" {
				path = "/"
			}
		}
	}
	return path
}

// getLimits returns the rate limits for a path and the bucket class they
// belong to: the path itself for an EndpointLimits entry, "" for the
// default limits.
func (rl *RateLimiter) getLimits(path string) (requestsPerMinute, burstSize int, class string) {
	if limit, ok := rl.config.EndpointLimits[path]; ok {
		rpm, burst := limit.RequestsPerMinute, limit.BurstSize
		if rpm <= 0 {
			rpm = rl.config.RequestsPerMinute
		}
		if burst <= 0 {
			burst = rl.config.BurstSize
		}
		return rpm, burst, path
	}
	return rl.config.RequestsPerMinute, rl.config.BurstSize, ""
}

// allow checks if a request is allowed and consumes a token.
func (rl *RateLimiter) allow(key string, requestsPerMinute, burstSize int) (RateLimitInfo, bool) {
	rl.mu.Lock()
	bucket, exists := rl.buckets[key]
	if !exists {
		bucket = newTokenBucket(requestsPerMinute, burstSize)
		rl.buckets[key] = bucket
	}
	rl.mu.Unlock()

	return bucket.take(requestsPerMinute)
}

// setHeaders sets standard rate limit response headers.
func (rl *RateLimiter) setHeaders(w http.ResponseWriter, info RateLimitInfo) {
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(info.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(info.Remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(info.ResetAt.Unix(), 10))
}

// handleLimitExceeded handles rate limit exceeded.
func (rl *RateLimiter) handleLimitExceeded(w http.ResponseWriter, r *http.Request, info RateLimitInfo) {
	if rl.config.OnLimitExceeded != nil {
		rl.config.OnLimitExceeded(w, r, info)
		return
	}

	w.Header().Set("Retry-After", strconv.Itoa(info.RetryAfter))
	http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
}

// cleanupLoop periodically removes expired buckets.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopCleanup:
			return
		}
	}
}

// cleanup removes buckets that haven't been used recently.
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	threshold := time.Now().Add(-5 * time.Minute)
	for key, bucket := range rl.buckets {
		bucket.mu.Lock()
		if bucket.lastRefill.Before(threshold) {
			delete(rl.buckets, key)
		}
		bucket.mu.Unlock()
	}
}

// Close stops the cleanup goroutine.
func (rl *RateLimiter) Close() {
	close(rl.stopCleanup)
}

// newTokenBucket creates a new token bucket.
func newTokenBucket(requestsPerMinute, burstSize int) *tokenBucket {
	return &tokenBucket{
		tokens:     float64(burstSize),
		maxTokens:  float64(burstSize),
		refillRate: float64(requestsPerMinute) / 60.0, // tokens per second
		lastRefill: time.Now(),
	}
}

// take attempts to take a token from the bucket.
func (tb *tokenBucket) take(requestsPerMinute int) (RateLimitInfo, bool) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()

	// Refill tokens based on time elapsed
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}
	tb.lastRefill = now

	// Calculate info
	info := RateLimitInfo{
		Limit:     requestsPerMinute,
		Remaining: int(tb.tokens),
		ResetAt:   now.Add(time.Minute),
	}

	// Check if we can take a token
	if tb.tokens < 1 {
		// Calculate retry after
		tokensNeeded := 1 - tb.tokens
		secondsToWait := tokensNeeded / tb.refillRate
		info.RetryAfter = int(secondsToWait) + 1
		info.Remaining = 0
		return info, false
	}

	// Take a token
	tb.tokens--
	info.Remaining = int(tb.tokens)
	return info, true
}

// RateLimitMiddleware creates rate limiting middleware with default config.
func RateLimitMiddleware(requestsPerMinute, burstSize int) func(http.Handler) http.Handler {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMinute: requestsPerMinute,
		BurstSize:         burstSize,
	})
	return rl.Middleware()
}
