package systemauthsvc

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"

	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/session/middleware"
)

// dpopReplayKeyPrefix namespaces SystemAuth's DPoP proof identifiers in
// Redis.
const dpopReplayKeyPrefix = "systemauth:dpop-jti:"

// dpopReplayCache returns the option setting the DPoP replay cache:
// Options.DPoPReplayCache when given, otherwise a Redis cache when
// dpop.replay_cache_redis_url is set, otherwise none (SystemAuth then keeps
// an in-memory cache, which suits one instance).
func (s *Service) dpopReplayCache(c *Config, opts Options, logger *slog.Logger) ([]systemauth.Option, error) {
	if opts.DPoPReplayCache != nil {
		return []systemauth.Option{systemauth.WithDPoPReplayCache(opts.DPoPReplayCache)}, nil
	}
	if c.DPoP.ReplayCacheRedisURL == "" {
		return nil, nil
	}
	ropts, err := redis.ParseURL(c.DPoP.ReplayCacheRedisURL)
	if err != nil {
		return nil, fmt.Errorf("systemauthsvc: dpop.replay_cache_redis_url: %w", err)
	}
	client := redis.NewClient(ropts)
	s.dpopRedis = client
	logger.Info("DPoP proofs checked against a shared Redis replay cache", "addr", ropts.Addr)
	return []systemauth.Option{systemauth.WithDPoPReplayCache(middleware.NewRedisReplayCache(client, dpopReplayKeyPrefix))}, nil
}

// closeDPoP releases the Redis client New opened for the replay cache.
func (s *Service) closeDPoP() error {
	if s.dpopRedis == nil {
		return nil
	}
	err := s.dpopRedis.Close()
	s.dpopRedis = nil
	if err != nil && !errors.Is(err, redis.ErrClosed) {
		return fmt.Errorf("closing the DPoP replay cache: %w", err)
	}
	return nil
}
