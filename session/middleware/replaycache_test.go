package middleware

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func testReplayCache(t *testing.T, c ReplayCache) {
	t.Helper()
	ctx := context.Background()
	key := "jkt:" + time.Now().Format(time.RFC3339Nano)
	exp := time.Now().Add(time.Minute)
	replayed, err := c.Use(ctx, key, exp)
	if err != nil || replayed {
		t.Fatalf("first use: replayed=%v err=%v", replayed, err)
	}
	replayed, err = c.Use(ctx, key, exp)
	if err != nil || !replayed {
		t.Fatalf("second use: replayed=%v err=%v, want replayed", replayed, err)
	}
}

func TestMemoryReplayCache(t *testing.T) {
	testReplayCache(t, NewMemoryReplayCache())

	c := NewMemoryReplayCache()
	ctx := context.Background()
	if _, err := c.Use(ctx, "k", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if replayed, err := c.Use(ctx, "k", time.Now().Add(time.Minute)); err != nil || replayed {
		t.Errorf("expired entry still counted: replayed=%v err=%v", replayed, err)
	}
}

// TestRedisReplayCache runs against a real Redis when
// SYSTEMFORGE_TEST_REDIS_ADDR is set.
func TestRedisReplayCache(t *testing.T) {
	addr := os.Getenv("SYSTEMFORGE_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("SYSTEMFORGE_TEST_REDIS_ADDR not set")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing redis client: %v", err)
		}
	})
	testReplayCache(t, NewRedisReplayCache(client, "dpop-jti-test:"))
}
