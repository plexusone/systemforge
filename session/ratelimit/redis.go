package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisStorage is a Redis-backed rate limit storage using sliding window algorithm.
// Suitable for distributed deployments where multiple instances share rate limit state.
type RedisStorage struct {
	client    redis.UniversalClient
	keyPrefix string
}

// RedisOption configures RedisStorage.
type RedisOption func(*RedisStorage)

// WithKeyPrefix sets a prefix for all rate limit keys in Redis.
func WithKeyPrefix(prefix string) RedisOption {
	return func(r *RedisStorage) {
		r.keyPrefix = prefix
	}
}

// NewRedisStorage creates a new Redis-backed rate limit storage.
// The client can be *redis.Client, *redis.ClusterClient, or any UniversalClient.
func NewRedisStorage(client redis.UniversalClient, opts ...RedisOption) *RedisStorage {
	r := &RedisStorage{
		client:    client,
		keyPrefix: "ratelimit:",
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Lua script for atomic sliding window rate limiting.
// Returns: [allowed (0/1), remaining, reset_at_unix]
var slidingWindowScript = redis.NewScript(`
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local now_ms = tonumber(ARGV[3])

-- Remove expired entries
local window_start = now_ms - window_ms
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- Count current entries
local count = redis.call('ZCARD', key)

-- Check if under limit
if count < limit then
    -- Add new entry with current timestamp as score
    redis.call('ZADD', key, now_ms, now_ms .. ':' .. math.random())
    -- Set expiration on the key
    redis.call('PEXPIRE', key, window_ms)

    local remaining = limit - count - 1
    local reset_at = now_ms + window_ms
    return {1, remaining, reset_at}
else
    -- Get the oldest entry to calculate retry-after
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local reset_at = now_ms + window_ms
    if oldest and #oldest >= 2 then
        reset_at = tonumber(oldest[2]) + window_ms
    end
    return {0, 0, reset_at}
end
`)

// Allow implements Storage.Allow using a sliding window algorithm with Redis.
func (r *RedisStorage) Allow(ctx context.Context, key string, limit Limit) (Result, error) {
	fullKey := r.keyPrefix + key

	burst := limit.Burst
	if burst == 0 {
		burst = limit.Rate
	}

	now := time.Now()
	nowMs := now.UnixMilli()
	windowMs := limit.Period.Milliseconds()

	result, err := slidingWindowScript.Run(ctx, r.client, []string{fullKey},
		burst,
		windowMs,
		nowMs,
	).Slice()
	if err != nil {
		return Result{}, fmt.Errorf("%w: %v", ErrStorageFailure, err)
	}

	if len(result) != 3 {
		return Result{}, fmt.Errorf("%w: unexpected result length", ErrStorageFailure)
	}

	allowed := result[0].(int64) == 1
	remaining := int(result[1].(int64))
	resetAtMs := result[2].(int64)
	resetAt := time.UnixMilli(resetAtMs)

	var retryAfter time.Duration
	if !allowed {
		retryAfter = max(resetAt.Sub(now), 0)
	}

	return Result{
		Allowed:    allowed,
		Remaining:  remaining,
		ResetAt:    resetAt,
		RetryAfter: retryAfter,
	}, nil
}

// Reset implements Storage.Reset.
func (r *RedisStorage) Reset(ctx context.Context, key string) error {
	fullKey := r.keyPrefix + key
	return r.client.Del(ctx, fullKey).Err()
}

// Close implements Storage.Close.
// Note: This does NOT close the Redis client since it may be shared.
func (r *RedisStorage) Close() error {
	return nil
}

// RedisConfig contains configuration for connecting to Redis.
type RedisConfig struct {
	// Addr is the Redis server address (e.g., "localhost:6379").
	Addr string

	// Password is the Redis password (optional).
	Password string

	// DB is the Redis database number (default 0).
	DB int

	// PoolSize is the maximum number of connections (default 10).
	PoolSize int

	// Cluster enables Redis Cluster mode.
	Cluster bool

	// ClusterAddrs are the cluster node addresses (used when Cluster is true).
	ClusterAddrs []string
}

// NewRedisClient creates a Redis client from configuration.
func NewRedisClient(cfg *RedisConfig) redis.UniversalClient {
	if cfg.Cluster {
		return redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:    cfg.ClusterAddrs,
			Password: cfg.Password,
			PoolSize: cfg.PoolSize,
		})
	}

	poolSize := cfg.PoolSize
	if poolSize == 0 {
		poolSize = 10
	}

	return redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
		PoolSize: poolSize,
	})
}
