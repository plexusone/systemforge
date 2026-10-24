package bff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// failingStore wraps a memory store and fails Get or Delete on demand.
type failingStore struct {
	*MemoryStore
	getErr    error
	deleteErr error
}

func (s *failingStore) Get(ctx context.Context, id string) (*Session, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.MemoryStore.Get(ctx, id)
}

func (s *failingStore) Delete(ctx context.Context, id string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.MemoryStore.Delete(ctx, id)
}

func newLogoutFixture(t *testing.T, onLogout func(context.Context, *Session) error) (*failingStore, *Handler, *Session) {
	t.Helper()
	store := &failingStore{MemoryStore: NewMemoryStore(DefaultStoreConfig())}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("closing store: %v", err)
		}
	})
	h, err := NewHandler(HandlerConfig{
		Store:          store,
		AllowedOrigins: []string{"https://example.com"},
		OnLogout:       onLogout,
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession(uuid.New(), "at", "rt", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	return store, h, sess
}

func doLogout(t *testing.T, h *Handler, sessionID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("Origin", "https://example.com")
	req.AddCookie(&http.Cookie{Name: h.CookieManager().Config().Name, Value: sessionID, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	rr := httptest.NewRecorder()
	h.Router().ServeHTTP(rr, req)
	return rr
}

func cookieCleared(rr *httptest.ResponseRecorder) bool {
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestLogout_DeleteFailureFailsClosed(t *testing.T) {
	store, h, sess := newLogoutFixture(t, nil)
	store.deleteErr = errors.New("store unavailable")

	rr := doLogout(t, h, sess.ID)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if cookieCleared(rr) {
		t.Error("cookie cleared although the session was not deleted")
	}
	if !strings.Contains(rr.Body.String(), "logout_failed") {
		t.Errorf("body = %q, want logout_failed", rr.Body.String())
	}
}

func TestLogout_GetFailureFailsClosed(t *testing.T) {
	store, h, sess := newLogoutFixture(t, nil)
	store.getErr = errors.New("store unavailable")

	rr := doLogout(t, h, sess.ID)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if cookieCleared(rr) {
		t.Error("cookie cleared although the session was not deleted")
	}
}

func TestLogout_HookFailureReportedButSessionDeleted(t *testing.T) {
	store, h, sess := newLogoutFixture(t, func(context.Context, *Session) error {
		return errors.New("revocation endpoint down")
	})

	rr := doLogout(t, h, sess.ID)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(rr.Body.String(), "revocation_failed") {
		t.Errorf("body = %q, want revocation_failed", rr.Body.String())
	}
	if !cookieCleared(rr) {
		t.Error("cookie not cleared")
	}
	if _, err := store.MemoryStore.Get(context.Background(), sess.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("session still present after logout: err = %v", err)
	}
}

func TestLogout_Success(t *testing.T) {
	called := false
	store, h, sess := newLogoutFixture(t, func(context.Context, *Session) error {
		called = true
		return nil
	})

	rr := doLogout(t, h, sess.ID)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !called {
		t.Error("OnLogout not called")
	}
	if !cookieCleared(rr) {
		t.Error("cookie not cleared")
	}
	if _, err := store.MemoryStore.Get(context.Background(), sess.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("session still present after logout: err = %v", err)
	}
}
