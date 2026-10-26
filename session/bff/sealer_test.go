package bff

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grokify/goauth/dpop"
	kvsmemory "github.com/plexusone/omnistorage-core/kvs/backend/memory"

	"github.com/plexusone/systemforge/keys"
)

// *keys.Keys must satisfy PurposeKeys so NewKeysSealer can take it.
var _ PurposeKeys = (*keys.Keys)(nil)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func testSealer(t *testing.T) *KeyringSealer {
	t.Helper()
	s, err := NewKeyringSealer("k1", map[string][]byte{"k1": testKey(1)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKeyringSealer_RoundTripAndRotation(t *testing.T) {
	ctx := context.Background()
	old, err := NewKeyringSealer("k1", map[string][]byte{"k1": testKey(1)})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := old.Seal(ctx, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}

	rotated, err := NewKeyringSealer("k2", map[string][]byte{"k1": testKey(1), "k2": testKey(2)})
	if err != nil {
		t.Fatal(err)
	}
	pt, err := rotated.Open(ctx, sealed, []byte("aad"))
	if err != nil || string(pt) != "secret" {
		t.Fatalf("Open with rotated keyring = %q, %v", pt, err)
	}
	if _, err := rotated.Open(ctx, sealed, []byte("other")); err == nil {
		t.Error("Open with wrong aad succeeded")
	}

	retired, err := NewKeyringSealer("k2", map[string][]byte{"k2": testKey(2)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retired.Open(ctx, sealed, []byte("aad")); !errors.Is(err, ErrUnknownSealingKey) {
		t.Errorf("Open after key removal: err = %v, want ErrUnknownSealingKey", err)
	}
}

func TestNewKeyringSealer_Validation(t *testing.T) {
	if _, err := NewKeyringSealer("missing", map[string][]byte{"k1": testKey(1)}); err == nil {
		t.Error("accepted an active key ID not in the keyring")
	}
	if _, err := NewKeyringSealer("k1", map[string][]byte{"k1": []byte("short")}); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("short key: err = %v, want ErrInvalidKeySize", err)
	}
}

// Tokens and the DPoP private key must not reach the backend in plaintext.
func TestOmniStorageStore_SealsSecretsAtRest(t *testing.T) {
	ctx := context.Background()
	backend := kvsmemory.New()
	store := newTestOmniStore(t, backend, "site-a")

	sess, err := NewSession(uuid.New(), "access-token-plaintext", "refresh-token-plaintext", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.SetDPoPKeyPair(kp); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}

	keys, err := backend.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal("backend holds no keys")
	}
	for _, k := range keys {
		raw, err := backend.Get(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		dpopKey := base64.StdEncoding.EncodeToString(sess.DPoPKeyPairJSON)
		for _, secret := range []string{"access-token-plaintext", "refresh-token-plaintext", dpopKey} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("backend key %q holds a secret in plaintext", k)
			}
		}
	}

	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != sess.AccessToken || got.RefreshToken != sess.RefreshToken || !bytes.Equal(got.DPoPKeyPairJSON, sess.DPoPKeyPairJSON) {
		t.Error("sealed session did not round-trip")
	}
}

func TestOmniStorageStore_RejectsPlaintextWhenSealing(t *testing.T) {
	ctx := context.Background()
	backend := kvsmemory.New()

	cfg := DefaultOmniStorageConfig()
	cfg.SiteID = "site-a"
	cfg.CleanupInterval = 0
	cfg.InsecurePlaintext = true
	plain, err := NewOmniStorageStoreWithKVS(backend, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession(uuid.New(), "at", "rt", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}

	sealing := newTestOmniStore(t, backend, "site-a")
	if _, err := sealing.Get(ctx, sess.ID); !errors.Is(err, ErrInvalidSession) {
		t.Errorf("Get of a plaintext session: err = %v, want ErrInvalidSession", err)
	}
}

func TestOmniStorageStore_RequiresSealer(t *testing.T) {
	cfg := DefaultOmniStorageConfig()
	cfg.SiteID = "site-a"
	if _, err := NewOmniStorageStoreWithKVS(kvsmemory.New(), cfg); !errors.Is(err, ErrSealerRequired) {
		t.Errorf("NewOmniStorageStoreWithKVS without sealer: err = %v, want ErrSealerRequired", err)
	}
	cfg.Backend = "redis"
	cfg.RedisURL = "redis://127.0.0.1:1"
	if _, err := NewOmniStorageStore(cfg); !errors.Is(err, ErrSealerRequired) {
		t.Errorf("NewOmniStorageStore(redis) without sealer: err = %v, want ErrSealerRequired", err)
	}
}

func TestKeyringSealer_RefusesOversizedData(t *testing.T) {
	s, err := NewKeyringSealer("k1", map[string][]byte{"k1": testKey(1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Seal(context.Background(), make([]byte, MaxSealPlaintext+1), nil); !errors.Is(err, ErrPlaintextTooLarge) {
		t.Fatalf("oversized data: %v, want ErrPlaintextTooLarge", err)
	}
}
