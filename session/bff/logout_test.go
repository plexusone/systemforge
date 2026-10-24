package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// recordingStore records Delete calls on top of a memory store.
type recordingStore struct {
	*MemoryStore
	deleted []string
}

func (s *recordingStore) Delete(ctx context.Context, id string) error {
	s.deleted = append(s.deleted, id)
	return s.MemoryStore.Delete(ctx, id)
}

func logout(t *testing.T, store Store, cookie string) {
	t.Helper()
	h, err := NewHandler(HandlerConfig{Store: store, AllowedOrigins: []string{"https://example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Origin", "https://example.com")
	req.AddCookie(&http.Cookie{Name: DefaultCookieName, Value: cookie, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	rr := httptest.NewRecorder()
	h.Router().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("logout: status %d", rr.Code)
	}
}

// Logout must pass the store only the ID of a session the store returned:
// a crafted cookie such as "user:<id>" names another record in stores that
// keep per-user session indexes in the same key space.
func TestLogoutDeletesOnlyAFoundSession(t *testing.T) {
	store := &recordingStore{MemoryStore: NewMemoryStore(DefaultStoreConfig())}
	t.Cleanup(func() { _ = store.Close() })

	for _, cookie := range []string{"user:" + uuid.NewString(), "not-a-session", "a b"} {
		logout(t, store, cookie)
	}
	if len(store.deleted) != 0 {
		t.Errorf("logout passed unverified IDs to Delete: %q", store.deleted)
	}

	sess, err := NewSession(uuid.New(), "at", "rt", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	logout(t, store, sess.ID)
	if len(store.deleted) != 1 || store.deleted[0] != sess.ID {
		t.Errorf("logout of a real session deleted %q", store.deleted)
	}
}

func TestValidSessionID(t *testing.T) {
	id, err := GenerateSessionID()
	if err != nil {
		t.Fatal(err)
	}
	if !ValidSessionID(id) {
		t.Errorf("generated ID %q rejected", id)
	}
	for _, bad := range []string{"", "user:1", "a b", "a;b"} {
		if ValidSessionID(bad) {
			t.Errorf("ValidSessionID(%q) = true", bad)
		}
	}
}
