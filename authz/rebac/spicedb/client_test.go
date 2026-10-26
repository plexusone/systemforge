package spicedb

import (
	"context"
	"encoding/hex"
	"testing"
	"time"
)

func TestNewPresharedKeyIsRandom(t *testing.T) {
	a, err := newPresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := newPresharedKey()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two preshared keys are equal")
	}
	raw, err := hex.DecodeString(a)
	if err != nil {
		t.Fatalf("key is not hex: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("key has %d bytes, want 32", len(raw))
	}
}

// TestEmbeddedClientServesInMemory checks that the embedded server answers
// through its in-memory listener.
func TestEmbeddedClientServesInMemory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := NewClient(ctx, DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing client: %v", err)
		}
	})
	if err := client.WriteSchema(ctx, BaseSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadSchema(ctx); err != nil {
		t.Fatal(err)
	}
}
