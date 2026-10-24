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
	cfg.Sealer = testSealer(t)
	store, err := NewOmniStorageStoreWithKVS(backend, cfg)
	if err != nil {
		t.Fatal(err)
	}
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

// Applications sharing one backend under the default configuration keep
// separate keys and user indexes, so one application's DeleteByUserID does
// not remove another's sessions.
func TestOmniStorageStore_DefaultKeyPrefixIsPerSite(t *testing.T) {
	ctx := context.Background()
	backend := kvsmemory.New()
	siteA := newTestOmniStore(t, backend, "site-a")
	siteB := newTestOmniStore(t, backend, "site-b")

	userID := uuid.New()
	sess, err := NewSession(userID, "at", "rt", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := siteA.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	keys, err := backend.List(ctx, "session:site-a:")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Fatal(`no keys under "session:site-a:"`)
	}
	if _, err := siteB.DeleteByUserID(ctx, userID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := siteA.Get(ctx, sess.ID); err != nil {
		t.Errorf("site-b DeleteByUserID removed a site-a session: %v", err)
	}
	if sessionKeyPrefix(OmniStorageConfig{SiteID: "s", KeyPrefix: "custom:"}) != "custom:" {
		t.Error("an explicit KeyPrefix was not kept")
	}
}
