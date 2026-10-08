package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewHandler_Validation(t *testing.T) {
	store := NewMemoryStore(DefaultStoreConfig())
	defer func() { _ = store.Close() }()

	tests := []struct {
		name    string
		config  HandlerConfig
		wantErr error
	}{
		{
			name:    "missing store",
			config:  HandlerConfig{AllowedOrigins: []string{"https://example.com"}},
			wantErr: ErrStoreRequired,
		},
		{
			name:    "missing origins",
			config:  HandlerConfig{Store: store},
			wantErr: ErrOriginsRequired,
		},
		{
			name: "valid config",
			config: HandlerConfig{
				Store:          store,
				AllowedOrigins: []string{"https://example.com"},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewHandler(tt.config)
			if err != tt.wantErr {
				t.Errorf("NewHandler() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandler_GetSession_NoSession(t *testing.T) {
	store := NewMemoryStore(DefaultStoreConfig())
	defer func() { _ = store.Close() }()

	handler, err := NewHandler(HandlerConfig{
		Store:          store,
		AllowedOrigins: []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	router := handler.Router()

	req := httptest.NewRequest("GET", "/session", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp SessionInfoResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.Authenticated {
		t.Error("expected authenticated = false")
	}
}

func TestHandler_GetSession_WithSession(t *testing.T) {
	store := NewMemoryStore(DefaultStoreConfig())
	defer func() { _ = store.Close() }()

	handler, err := NewHandler(HandlerConfig{
		Store:          store,
		AllowedOrigins: []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	// Create a session
	userID := uuid.New()
	session, err := NewSession(userID, "access_token", "refresh_token", time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	if err := store.Create(context.Background(), session); err != nil {
		t.Fatalf("store.Create() error = %v", err)
	}

	router := handler.Router()

	req := httptest.NewRequest("GET", "/session", nil)
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  "sf_session",
		Value: session.ID,
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp SessionInfoResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !resp.Authenticated {
		t.Error("expected authenticated = true")
	}
	if resp.UserID == nil || *resp.UserID != userID {
		t.Errorf("user_id = %v, want %v", resp.UserID, userID)
	}
}

func TestHandler_Logout(t *testing.T) {
	store := NewMemoryStore(DefaultStoreConfig())
	defer func() { _ = store.Close() }()

	logoutCalled := false
	handler, err := NewHandler(HandlerConfig{
		Store:          store,
		AllowedOrigins: []string{"https://example.com"},
		OnLogout: func(ctx context.Context, session *Session) error {
			logoutCalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	// Create a session
	userID := uuid.New()
	session, _ := NewSession(userID, "access_token", "refresh_token", time.Hour, 24*time.Hour)
	_ = store.Create(context.Background(), session)

	router := handler.Router()

	req := httptest.NewRequest("POST", "/logout", nil)
	req.Header.Set("Origin", "https://example.com")
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  "sf_session",
		Value: session.ID,
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	if !logoutCalled {
		t.Error("expected OnLogout hook to be called")
	}

	// Verify session was deleted
	_, err = store.Get(context.Background(), session.ID)
	if err != ErrSessionNotFound {
		t.Errorf("expected session to be deleted, got error: %v", err)
	}

	// Verify cookie was cleared
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "sf_session" && c.MaxAge == -1 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected session cookie to be cleared")
	}
}

func TestHandler_Refresh(t *testing.T) {
	store := NewMemoryStore(DefaultStoreConfig())
	defer func() { _ = store.Close() }()

	handler, err := NewHandler(HandlerConfig{
		Store:          store,
		AllowedOrigins: []string{"https://example.com"},
		OnRefresh: func(ctx context.Context, session *Session) (*TokenRefreshResult, error) {
			return &TokenRefreshResult{
				AccessToken:          "new_access_token",
				AccessTokenExpiresIn: time.Hour,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	// Create a session
	userID := uuid.New()
	session, _ := NewSession(userID, "old_access_token", "refresh_token", time.Hour, 24*time.Hour)
	_ = store.Create(context.Background(), session)

	router := handler.Router()

	req := httptest.NewRequest("POST", "/refresh", nil)
	req.Header.Set("Origin", "https://example.com")
	//nolint:gosec // G124: Test code - security attributes not needed for httptest
	req.AddCookie(&http.Cookie{
		Name:  "sf_session",
		Value: session.ID,
	})
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Verify session was updated
	updated, _ := store.Get(context.Background(), session.ID)
	if updated.AccessToken != "new_access_token" {
		t.Errorf("access_token = %q, want %q", updated.AccessToken, "new_access_token")
	}
}

func TestHandler_Refresh_NotConfigured(t *testing.T) {
	store := NewMemoryStore(DefaultStoreConfig())
	defer func() { _ = store.Close() }()

	handler, err := NewHandler(HandlerConfig{
		Store:          store,
		AllowedOrigins: []string{"https://example.com"},
		// OnRefresh not set
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	router := handler.Router()

	req := httptest.NewRequest("POST", "/refresh", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotImplemented)
	}
}

func TestHandler_OriginValidation(t *testing.T) {
	store := NewMemoryStore(DefaultStoreConfig())
	defer func() { _ = store.Close() }()

	handler, err := NewHandler(HandlerConfig{
		Store:          store,
		AllowedOrigins: []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	router := handler.Router()

	tests := []struct {
		name       string
		method     string
		origin     string
		wantStatus int
	}{
		{
			name:       "GET without origin - allowed (safe method)",
			method:     "GET",
			origin:     "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "POST without origin - forbidden",
			method:     "POST",
			origin:     "",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "POST with valid origin - allowed",
			method:     "POST",
			origin:     "https://example.com",
			wantStatus: http.StatusOK, // 200 for logout (or 501 for refresh without config)
		},
		{
			name:       "POST with invalid origin - forbidden",
			method:     "POST",
			origin:     "https://evil.com",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := "/session"
			if tt.method == "POST" {
				path = "/logout"
			}

			req := httptest.NewRequest(tt.method, path, nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandler_CreateSession(t *testing.T) {
	store := NewMemoryStore(DefaultStoreConfig())
	defer func() { _ = store.Close() }()

	createCalled := false
	handler, err := NewHandler(HandlerConfig{
		Store:          store,
		AllowedOrigins: []string{"https://example.com"},
		OnCreateSession: func(ctx context.Context, session *Session) error {
			createCalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	req.Header.Set("User-Agent", "TestBrowser/1.0")

	rec := httptest.NewRecorder()

	userID := uuid.New()
	session, err := handler.CreateSession(context.Background(), rec, req, CreateSessionParams{
		UserID:                userID,
		AccessToken:           "access_token",
		RefreshToken:          "refresh_token",
		AccessTokenExpiresIn:  time.Hour,
		RefreshTokenExpiresIn: 24 * time.Hour,
		Metadata:              map[string]string{"provider": "google"},
	})
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	if !createCalled {
		t.Error("expected OnCreateSession hook to be called")
	}

	if session.UserID != userID {
		t.Errorf("user_id = %v, want %v", session.UserID, userID)
	}

	if session.IPAddress != "192.168.1.100" {
		t.Errorf("ip_address = %q, want %q", session.IPAddress, "192.168.1.100")
	}

	if session.UserAgent != "TestBrowser/1.0" {
		t.Errorf("user_agent = %q, want %q", session.UserAgent, "TestBrowser/1.0")
	}

	if session.Metadata["provider"] != "google" {
		t.Errorf("metadata[provider] = %q, want %q", session.Metadata["provider"], "google")
	}

	// Verify cookie was set
	cookies := rec.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "sf_session" && c.Value == session.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected session cookie to be set")
	}

	// Verify session was stored
	stored, err := store.Get(context.Background(), session.ID)
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if stored.AccessToken != "access_token" {
		t.Errorf("stored access_token = %q, want %q", stored.AccessToken, "access_token")
	}
}
