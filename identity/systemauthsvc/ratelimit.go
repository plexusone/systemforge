package systemauthsvc

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"

	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/session/ratelimit"
)

// rateLimitKeyPrefix namespaces SystemAuth's rate limit counters in Redis.
const rateLimitKeyPrefix = "systemauth:ratelimit:"

// rateLimitStorage returns the option setting the storage every rate limit
// shares: Options.RateLimitStorage when given, otherwise Redis when
// rate_limit.redis_url is set, otherwise none (SystemAuth then keeps the
// counters in memory, which suits one instance).
func (s *Service) rateLimitStorage(c *Config, opts Options, logger *slog.Logger) ([]systemauth.Option, error) {
	if opts.RateLimitStorage != nil {
		return []systemauth.Option{systemauth.WithRateLimitStorage(opts.RateLimitStorage)}, nil
	}
	if c.RateLimit.RedisURL == "" {
		return nil, nil
	}
	ropts, err := redis.ParseURL(c.RateLimit.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("systemauthsvc: rate_limit.redis_url: %w", err)
	}
	client := redis.NewClient(ropts)
	s.rateRedis = client
	logger.Info("rate limits shared through Redis", "addr", ropts.Addr)
	return []systemauth.Option{systemauth.WithRateLimitStorage(ratelimit.NewRedisStorage(client, ratelimit.WithKeyPrefix(rateLimitKeyPrefix)))}, nil
}

// rateLimitsShared reports whether the rate limit counters are shared by
// every instance, or one instance is declared.
func rateLimitsShared(c *Config, opts Options) bool {
	return opts.RateLimitStorage != nil || c.RateLimit.RedisURL != "" || c.RateLimit.SingleInstance || c.DPoP.SingleInstance
}

// closeRateLimits releases the Redis client New opened for rate limits.
func (s *Service) closeRateLimits() error {
	if s.rateRedis == nil {
		return nil
	}
	err := s.rateRedis.Close()
	s.rateRedis = nil
	if err != nil && !errors.Is(err, redis.ErrClosed) {
		return fmt.Errorf("closing the rate limit storage: %w", err)
	}
	return nil
}
