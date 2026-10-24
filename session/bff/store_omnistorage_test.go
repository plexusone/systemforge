package bff

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	kvsmemory "github.com/plexusone/omnistorage-core/kvs/backend/memory"
)

func newTestOmniStore(t *testing.T, backend *kvsmemory.Store, siteID string) *OmniStorageStore {
	t.Helper()
	cfg := DefaultOmniStorageConfig()
	cfg.SiteID = siteID
	cfg.CleanupInterval = 0
	store := NewOmniStorageStoreWithKVS(backend, cfg)
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("closing store: %v", err)
		}
	})
	return store
}

// An Update (for example a token refresh) must keep the session's site,
// or the next Get under site isolation reports it missing.
func TestOmniStorageStore_UpdateKeepsSiteID(t *testing.T) {
	ctx := context.Background()
	store := newTestOmniStore(t, kvsmemory.New(), "site-a")

	sess, err := NewSession(uuid.New(), "at", "rt", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get after Create: %v", err)
	}
	got.AccessToken = "at2"
	if err := store.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err = store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get after Update: %v", err)
	}
	if got.AccessToken != "at2" {
		t.Errorf("AccessToken = %q, want at2", got.AccessToken)
	}
}

func TestOmniStorageStore_OtherSiteCannotRead(t *testing.T) {
	ctx := context.Background()
	backend := kvsmemory.New()
	siteA := newTestOmniStore(t, backend, "site-a")
	siteB := newTestOmniStore(t, backend, "site-b")

	sess, err := NewSession(uuid.New(), "at", "rt", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := siteA.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if _, err := siteB.Get(ctx, sess.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("site-b Get of a site-a session: err = %v, want ErrSessionNotFound", err)
	}
}

func TestNewOmniStorageStore_RedisRequiresSiteID(t *testing.T) {
	cfg := DefaultOmniStorageConfig()
	cfg.Backend = "redis"
	cfg.RedisURL = "redis://127.0.0.1:1"
	if _, err := NewOmniStorageStore(cfg); !errors.Is(err, ErrSiteIDRequired) {
		t.Fatalf("NewOmniStorageStore() error = %v, want ErrSiteIDRequired", err)
	}
}
