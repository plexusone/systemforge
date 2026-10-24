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

func TestSessionMiddleware_WithSession(t *testing.T) {
	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	cookieMgr := NewCookieManager(DefaultCookieConfig())

	// Create a session
	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)
	_ = store.Create(context.Background(), session)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := GetSession(r.Context())
		if s == nil {
			t.Error("Session not in context")
			http.Error(w, "no session", http.StatusInternalServerError)
			return
		}
		if s.ID != session.ID {
			t.Errorf("Session ID = %s, want %s", s.ID, session.ID)
		}
		w.WriteHeader(http.StatusOK)
	})

	middleware := SessionMiddleware(MiddlewareConfig{
		Store:         store,
		CookieManager: cookieMgr,
	})

	req := httptest.NewRequest("GET", "/", nil)
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  DefaultCookieName,
		Value: session.ID,
	})

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestSessionMiddleware_NoSession_NotRequired(t *testing.T) {
	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	cookieMgr := NewCookieManager(DefaultCookieConfig())

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := GetSession(r.Context())
		if s != nil {
			t.Error("Session should be nil when no cookie")
		}
		w.WriteHeader(http.StatusOK)
	})

	middleware := SessionMiddleware(MiddlewareConfig{
		Store:          store,
		CookieManager:  cookieMgr,
		RequireSession: false,
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestSessionMiddleware_NoSession_Required(t *testing.T) {
	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	cookieMgr := NewCookieManager(DefaultCookieConfig())

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	})

	middleware := SessionMiddleware(MiddlewareConfig{
		Store:          store,
		CookieManager:  cookieMgr,
		RequireSession: true,
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestSessionMiddleware_SessionNotFound(t *testing.T) {
	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	cookieMgr := NewCookieManager(DefaultCookieConfig())

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := SessionMiddleware(MiddlewareConfig{
		Store:          store,
		CookieManager:  cookieMgr,
		RequireSession: false,
	})

	req := httptest.NewRequest("GET", "/", nil)
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  DefaultCookieName,
		Value: "non-existent-session",
	})

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	// Should clear the cookie
	cookies := rr.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == DefaultCookieName {
			sessionCookie = c
			break
		}
	}

	if sessionCookie == nil || sessionCookie.MaxAge != -1 {
		t.Error("Should clear invalid session cookie")
	}

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d (not required)", rr.Code, http.StatusOK)
	}
}

func TestSessionMiddleware_SessionExpired(t *testing.T) {
	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	cookieMgr := NewCookieManager(DefaultCookieConfig())

	// Create an expired session
	session, _ := NewSession(uuid.New(), "token", "refresh", -time.Hour, -time.Hour)
	session.ExpiresAt = time.Now().Add(-time.Hour)
	_ = store.Create(context.Background(), session)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	})

	middleware := SessionMiddleware(MiddlewareConfig{
		Store:         store,
		CookieManager: cookieMgr,
	})

	req := httptest.NewRequest("GET", "/", nil)
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  DefaultCookieName,
		Value: session.ID,
	})

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestSessionMiddleware_TouchOnAccess(t *testing.T) {
	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	cookieMgr := NewCookieManager(DefaultCookieConfig())

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)
	originalLastAccessed := session.LastAccessedAt
	_ = store.Create(context.Background(), session)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := SessionMiddleware(MiddlewareConfig{
		Store:         store,
		CookieManager: cookieMgr,
		TouchOnAccess: true,
	})

	time.Sleep(10 * time.Millisecond)

	req := httptest.NewRequest("GET", "/", nil)
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  DefaultCookieName,
		Value: session.ID,
	})

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	// Check that LastAccessedAt was updated
	updatedSession, _ := store.Get(context.Background(), session.ID)
	if !updatedSession.LastAccessedAt.After(originalLastAccessed) {
		t.Error("LastAccessedAt should be updated when TouchOnAccess is true")
	}
}

func TestSessionMiddleware_OnSessionLoad(t *testing.T) {
	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	cookieMgr := NewCookieManager(DefaultCookieConfig())

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)
	_ = store.Create(context.Background(), session)

	loadHookCalled := false
	middleware := SessionMiddleware(MiddlewareConfig{
		Store:         store,
		CookieManager: cookieMgr,
		OnSessionLoad: func(ctx context.Context, s *Session) error {
			loadHookCalled = true
			if s.ID != session.ID {
				t.Errorf("OnSessionLoad got session %s, want %s", s.ID, session.ID)
			}
			return nil
		},
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  DefaultCookieName,
		Value: session.ID,
	})

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !loadHookCalled {
		t.Error("OnSessionLoad hook should be called")
	}
}

func TestSessionMiddleware_OnSessionLoad_Error(t *testing.T) {
	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	cookieMgr := NewCookieManager(DefaultCookieConfig())

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)
	_ = store.Create(context.Background(), session)

	middleware := SessionMiddleware(MiddlewareConfig{
		Store:         store,
		CookieManager: cookieMgr,
		OnSessionLoad: func(ctx context.Context, s *Session) error {
			return errors.New("session validation failed")
		},
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	})

	req := httptest.NewRequest("GET", "/", nil)
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  DefaultCookieName,
		Value: session.ID,
	})

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestSessionMiddleware_CustomErrorHandlers(t *testing.T) {
	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	cookieMgr := NewCookieManager(DefaultCookieConfig())

	noSessionCalled := false
	middleware := SessionMiddleware(MiddlewareConfig{
		Store:          store,
		CookieManager:  cookieMgr,
		RequireSession: true,
		OnNoSession: func(w http.ResponseWriter, r *http.Request) {
			noSessionCalled = true
			http.Error(w, "Custom no session", http.StatusTeapot)
		},
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	})

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !noSessionCalled {
		t.Error("OnNoSession should be called")
	}
	if rr.Code != http.StatusTeapot {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusTeapot)
	}
}

func TestGetSession_NotSet(t *testing.T) {
	ctx := context.Background()
	session := GetSession(ctx)
	if session != nil {
		t.Error("GetSession() should return nil for empty context")
	}
}

func TestRequireSessionMiddleware(t *testing.T) {
	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	cookieMgr := NewCookieManager(DefaultCookieConfig())

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called without session")
	})

	middleware := RequireSessionMiddleware(store, cookieMgr)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestOptionalSessionMiddleware(t *testing.T) {
	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	cookieMgr := NewCookieManager(DefaultCookieConfig())

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := OptionalSessionMiddleware(store, cookieMgr)

	// Without session - should pass
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}
}
