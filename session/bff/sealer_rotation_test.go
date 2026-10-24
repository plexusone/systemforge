package bff

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	kvsmemory "github.com/plexusone/omnistorage-core/kvs/backend/memory"
)

func keyring(t *testing.T, active string, ids ...string) *KeyringSealer {
	t.Helper()
	keys := map[string][]byte{}
	for _, id := range ids {
		keys[id] = testKey(id[len(id)-1])
	}
	s, err := NewKeyringSealer(active, keys)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newTestSession(t *testing.T) *Session {
	t.Helper()
	s, err := NewSession(uuid.New(), "at-"+uuid.NewString(), "rt-"+uuid.NewString(), time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// testSealerRotation walks a sealing-key rotation over one store backend:
// pre-stage N (in the ring, not active), promote N with N-1 kept, roll the
// promotion back, and rotate again. Every session written along the way
// must open at every step, including sessions sealed with N after the
// rollback; only the next promotion drops N-2.
func testSealerRotation(t *testing.T, open func(t *testing.T, sealer SessionSealer) Store) {
	ctx := context.Background()
	steady := keyring(t, "k1", "k1")
	preStage := keyring(t, "k1", "k1", "k2")
	promote := keyring(t, "k2", "k1", "k2")
	nextPreStage := keyring(t, "k2", "k1", "k2", "k3")
	nextPromote := keyring(t, "k3", "k2", "k3")

	var written []*Session
	sealedWith := map[string]string{}
	write := func(sealer SessionSealer, kid string) Store {
		t.Helper()
		st := open(t, sealer)
		s := newTestSession(t)
		if err := st.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
		written = append(written, s)
		sealedWith[s.ID] = kid
		return st
	}
	readAll := func(step string, st Store) {
		t.Helper()
		for _, want := range written {
			got, err := st.Get(ctx, want.ID)
			if err != nil {
				t.Errorf("%s: session sealed with %s: %v", step, sealedWith[want.ID], err)
				continue
			}
			if got.AccessToken != want.AccessToken || got.RefreshToken != want.RefreshToken {
				t.Errorf("%s: session sealed with %s did not round-trip", step, sealedWith[want.ID])
			}
		}
	}

	write(steady, "k1")
	readAll("pre-stage", write(preStage, "k1"))
	readAll("promote", write(promote, "k2"))
	readAll("roll back", write(preStage, "k1"))
	readAll("promote again", write(promote, "k2"))
	readAll("next pre-stage", write(nextPreStage, "k2"))

	last := open(t, nextPromote)
	for _, s := range written {
		_, err := last.Get(ctx, s.ID)
		if sealedWith[s.ID] == "k1" {
			if err == nil {
				t.Errorf("next promote: session sealed with N-2 (k1) still opens")
			}
		} else if err != nil {
			t.Errorf("next promote: session sealed with %s: %v", sealedWith[s.ID], err)
		}
	}
}

func TestOmniStorageStore_SealerRotationRollback(t *testing.T) {
	backend := kvsmemory.New()
	testSealerRotation(t, func(t *testing.T, sealer SessionSealer) Store {
		cfg := DefaultOmniStorageConfig()
		cfg.SiteID = "site-a"
		cfg.CleanupInterval = 0
		cfg.Sealer = sealer
		st, err := NewOmniStorageStoreWithKVS(backend, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := st.Close(); err != nil {
				t.Errorf("closing store: %v", err)
			}
		})
		return st
	})
}
