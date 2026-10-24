package bff

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSessionLifetimeExceeded(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		created   time.Time
		last      time.Time
		idle, max time.Duration
		want      bool
	}{
		{"fresh", now.Add(-time.Minute), now.Add(-time.Minute), time.Hour, 24 * time.Hour, false},
		{"idle", now.Add(-3 * time.Hour), now.Add(-2 * time.Hour), time.Hour, 24 * time.Hour, true},
		{"too old though active", now.Add(-25 * time.Hour), now, time.Hour, 24 * time.Hour, true},
		{"never accessed uses created", now.Add(-2 * time.Hour), time.Time{}, time.Hour, 24 * time.Hour, true},
		{"no created at fails max", time.Time{}, now, time.Hour, 24 * time.Hour, true},
		{"checks disabled", now.Add(-1000 * time.Hour), now.Add(-1000 * time.Hour), 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{CreatedAt: tt.created, LastAccessedAt: tt.last}
			if got := s.LifetimeExceeded(now, tt.idle, tt.max); got != tt.want {
				t.Errorf("LifetimeExceeded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func storeAgedSession(t *testing.T, store Store, created, lastAccessed time.Time) *Session {
	t.Helper()
	sess, err := NewSession(uuid.New(), "at", "rt", time.Hour, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sess.CreatedAt = created
	sess.LastAccessedAt = lastAccessed
	if err := store.Create(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	return sess
}

func sessionCookie(name, id string) *http.Cookie {
	return &http.Cookie{Name: name, Value: id, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func TestSessionMiddleware_EnforcesIdleTimeout(t *testing.T) {
	store := NewMemoryStore(DefaultStoreConfig())
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("closing store: %v", err)
		}
	})
	cm := NewCookieManager(DefaultCookieConfig())
	now := time.Now()
	idle := storeAgedSession(t, store, now.Add(-2*time.Hour), now.Add(-90*time.Minute))
	active := storeAgedSession(t, store, now.Add(-2*time.Hour), now.Add(-time.Minute))

	mw := SessionMiddleware(MiddlewareConfig{
		Store:          store,
		CookieManager:  cm,
		RequireSession: true,
		IdleTimeout:    time.Hour,
	})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))

	for _, tc := range []struct {
		sess *Session
		want int
	}{{idle, http.StatusUnauthorized}, {active, http.StatusOK}} {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(sessionCookie(cm.Config().Name, tc.sess.ID))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tc.want {
			t.Errorf("session %s: status = %d, want %d", tc.sess.ID, rr.Code, tc.want)
		}
	}
	if _, err := store.Get(context.Background(), idle.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("idle session not deleted: err = %v", err)
	}
}

func TestSessionMiddleware_DefaultMaxLifetime(t *testing.T) {
	store := NewMemoryStore(DefaultStoreConfig())
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("closing store: %v", err)
		}
	})
	cm := NewCookieManager(DefaultCookieConfig())
	old := storeAgedSession(t, store, time.Now().Add(-DefaultMaxLifetime-time.Hour), time.Now())

	h := RequireSessionMiddleware(store, cm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(sessionCookie(cm.Config().Name, old.ID))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d for a session past DefaultMaxLifetime", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRefresh_CannotExtendPastMaxLifetime(t *testing.T) {
	store := NewMemoryStore(DefaultStoreConfig())
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("closing store: %v", err)
		}
	})
	h, err := NewHandler(HandlerConfig{
		Store:          store,
		AllowedOrigins: []string{"https://example.com"},
		MaxLifetime:    24 * time.Hour,
		OnRefresh: func(context.Context, *Session) (*TokenRefreshResult, error) {
			return &TokenRefreshResult{
				AccessToken:           "at2",
				RefreshToken:          "rt2",
				AccessTokenExpiresIn:  time.Hour,
				RefreshTokenExpiresIn: 30 * 24 * time.Hour,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	refresh := func(id string) int {
		req := httptest.NewRequest(http.MethodPost, "/refresh", nil)
		req.Header.Set("Origin", "https://example.com")
		req.AddCookie(sessionCookie(h.CookieManager().Config().Name, id))
		rr := httptest.NewRecorder()
		h.Router().ServeHTTP(rr, req)
		return rr.Code
	}

	created := time.Now().Add(-time.Hour)
	young := storeAgedSession(t, store, created, time.Now())
	if code := refresh(young.ID); code != http.StatusOK {
		t.Fatalf("refresh of young session: status = %d", code)
	}
	got, err := store.Get(context.Background(), young.ID)
	if err != nil {
		t.Fatal(err)
	}
	if limit := created.Add(24 * time.Hour); got.ExpiresAt.After(limit) {
		t.Errorf("ExpiresAt = %v, extended past MaxLifetime limit %v", got.ExpiresAt, limit)
	}

	old := storeAgedSession(t, store, time.Now().Add(-25*time.Hour), time.Now())
	if code := refresh(old.ID); code != http.StatusUnauthorized {
		t.Errorf("refresh of session past MaxLifetime: status = %d, want %d", code, http.StatusUnauthorized)
	}
}
