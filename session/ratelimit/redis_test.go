package ratelimit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestNewWindowMember_Unique(t *testing.T) {
	const nowMs = int64(1700000000000)
	seen := make(map[string]bool)
	for range 1000 {
		m, err := newWindowMember(nowMs)
		if err != nil {
			t.Fatalf("newWindowMember: %v", err)
		}
		if seen[m] {
			t.Fatalf("duplicate member %q for the same millisecond", m)
		}
		seen[m] = true
	}
}

// TestSlidingWindowScript_SameMillisecond runs against a real Redis when
// SYSTEMFORGE_TEST_REDIS_ADDR is set. Two requests stamped with the same
// millisecond must both be counted.
func TestSlidingWindowScript_SameMillisecond(t *testing.T) {
	addr := os.Getenv("SYSTEMFORGE_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("SYSTEMFORGE_TEST_REDIS_ADDR not set")
	}
	ctx := context.Background()
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing redis client: %v", err)
		}
	})

	key := "ratelimit-test:" + time.Now().Format(time.RFC3339Nano)
	t.Cleanup(func() {
		if err := client.Del(ctx, key).Err(); err != nil {
			t.Errorf("deleting test key: %v", err)
		}
	})

	nowMs := time.Now().UnixMilli()
	for range 2 {
		member, err := newWindowMember(nowMs)
		if err != nil {
			t.Fatal(err)
		}
		if err := slidingWindowScript.Run(ctx, client, []string{key}, 10, 60000, nowMs, member).Err(); err != nil {
			t.Fatalf("running script: %v", err)
		}
	}
	n, err := client.ZCard(ctx, key).Result()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("ZCARD = %d, want 2: same-millisecond requests collapsed", n)
	}
}
