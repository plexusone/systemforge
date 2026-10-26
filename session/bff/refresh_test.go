package bff

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewRefresher(t *testing.T) {
	config := DefaultRefreshConfig()
	config.TokenEndpoint = "https://auth.example.com/token"
	config.ClientID = "test-client"

	refresher, err := NewRefresher(config)
	if err != nil {
		t.Fatalf("NewRefresher() error: %v", err)
	}

	if refresher == nil {
		t.Fatal("NewRefresher() returned nil")
	}
}

func TestNewRefresher_NoTokenEndpoint(t *testing.T) {
	config := DefaultRefreshConfig()
	config.ClientID = "test-client"

	_, err := NewRefresher(config)
	if err != ErrTokenEndpointRequired {
		t.Errorf("NewRefresher() error = %v, want ErrTokenEndpointRequired", err)
	}
}

func TestDefaultRefreshConfig(t *testing.T) {
	config := DefaultRefreshConfig()

	if !config.UseDPoP {
		t.Error("UseDPoP = false, want true")
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", config.Timeout)
	}
	if config.RefreshThreshold != 5*time.Minute {
		t.Errorf("RefreshThreshold = %v, want 5m", config.RefreshThreshold)
	}
}

func TestRefresher_RefreshSession(t *testing.T) {
	// Create mock token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Method = %s, want POST", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %s, want application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		}

		// Parse form (test mock server, body size not a concern)
		if err := r.ParseForm(); err != nil { //nolint:gosec // G120: Test mock server
			t.Fatalf("ParseForm() error: %v", err)
		}

		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %s, want refresh_token", r.Form.Get("grant_type"))
		}

		if r.Form.Get("refresh_token") == "" {
			t.Error("refresh_token should not be empty")
		}

		// Return token response
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Test mock OAuth token response
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "new-access-token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "new-refresh-token",
		})
	}))
	defer tokenServer.Close()

	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	config := DefaultRefreshConfig()
	config.TokenEndpoint = tokenServer.URL
	config.ClientID = "test-client"
	config.Store = store
	config.UseDPoP = false // Disable for simpler test

	refresher, _ := NewRefresher(config)

	// Create session with expiring access token
	session, _ := NewSession(uuid.New(), "old-access-token", "old-refresh-token", time.Hour, 24*time.Hour)
	_ = store.Create(context.Background(), session)

	// Refresh
	err := refresher.RefreshSession(context.Background(), session)
	if err != nil {
		t.Fatalf("RefreshSession() error: %v", err)
	}

	// Verify tokens were updated
	if session.AccessToken != "new-access-token" {
		t.Errorf("AccessToken = %s, want new-access-token", session.AccessToken)
	}
	if session.RefreshToken != "new-refresh-token" {
		t.Errorf("RefreshToken = %s, want new-refresh-token", session.RefreshToken)
	}
}

func TestRefresher_RefreshSession_WithDPoP(t *testing.T) {
	var receivedDPoP string
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedDPoP = r.Header.Get("DPoP")

		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Test mock OAuth token response
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "dpop-bound-token",
			TokenType:   "DPoP",
			ExpiresIn:   3600,
		})
	}))
	defer tokenServer.Close()

	config := DefaultRefreshConfig()
	config.TokenEndpoint = tokenServer.URL
	config.ClientID = "test-client"
	config.UseDPoP = true

	refresher, _ := NewRefresher(config)

	session, _ := NewSession(uuid.New(), "old-token", "refresh-token", time.Hour, 24*time.Hour)

	err := refresher.RefreshSession(context.Background(), session)
	if err != nil {
		t.Fatalf("RefreshSession() error: %v", err)
	}

	// Verify DPoP proof was sent
	if receivedDPoP == "" {
		t.Error("DPoP header should be sent when UseDPoP is true")
	}

	// Verify session has DPoP key pair
	if !session.HasDPoP() {
		t.Error("Session should have DPoP key pair after refresh with UseDPoP")
	}
}

func TestRefresher_RefreshSession_ExpiredRefreshToken(t *testing.T) {
	config := DefaultRefreshConfig()
	config.TokenEndpoint = "https://auth.example.com/token"
	config.ClientID = "test-client"

	refresher, _ := NewRefresher(config)

	// Create session with expired refresh token
	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, -time.Hour)
	session.RefreshTokenExpiresAt = time.Now().Add(-time.Hour)

	err := refresher.RefreshSession(context.Background(), session)
	if err != ErrRefreshTokenExpired {
		t.Errorf("RefreshSession() error = %v, want ErrRefreshTokenExpired", err)
	}
}

func TestRefresher_RefreshSession_ServerError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(TokenErrorResponse{
			Error:            "invalid_grant",
			ErrorDescription: "Refresh token is invalid",
		})
	}))
	defer tokenServer.Close()

	config := DefaultRefreshConfig()
	config.TokenEndpoint = tokenServer.URL
	config.ClientID = "test-client"
	config.UseDPoP = false

	refresher, _ := NewRefresher(config)

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, 24*time.Hour)

	err := refresher.RefreshSession(context.Background(), session)
	if err == nil {
		t.Error("RefreshSession() should error on server error")
	}
}

func TestRefresher_Middleware_NoSession(t *testing.T) {
	config := DefaultRefreshConfig()
	config.TokenEndpoint = "https://auth.example.com/token"
	config.ClientID = "test-client"

	refresher, _ := NewRefresher(config)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := refresher.Middleware()

	req := httptest.NewRequest("GET", "/api/users", nil)
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called when no session")
	}
}

func TestRefresher_Middleware_ValidToken(t *testing.T) {
	config := DefaultRefreshConfig()
	config.TokenEndpoint = "https://auth.example.com/token"
	config.ClientID = "test-client"

	refresher, _ := NewRefresher(config)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := refresher.Middleware()

	// Create session with valid token (not needing refresh)
	session, _ := NewSession(uuid.New(), "valid-token", "refresh", time.Hour, 24*time.Hour)

	req := httptest.NewRequest("GET", "/api/users", nil)
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called for valid token")
	}
}

func TestRefresher_Middleware_TokenNeedsRefresh(t *testing.T) {
	refreshCalled := false
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCalled = true
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Test mock OAuth token response
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "refreshed-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer tokenServer.Close()

	config := DefaultRefreshConfig()
	config.TokenEndpoint = tokenServer.URL
	config.ClientID = "test-client"
	config.UseDPoP = false
	config.RefreshThreshold = 30 * time.Minute

	refresher, _ := NewRefresher(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := refresher.Middleware()

	// Create session that needs refresh (expires in 15 min, threshold is 30 min)
	session, _ := NewSession(uuid.New(), "expiring-token", "refresh", 15*time.Minute, 24*time.Hour)

	req := httptest.NewRequest("GET", "/api/users", nil)
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !refreshCalled {
		t.Error("Token server should be called when token needs refresh")
	}
}

func TestRefreshHandler_Success(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Test mock OAuth token response
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "refreshed-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer tokenServer.Close()

	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	config := DefaultRefreshConfig()
	config.TokenEndpoint = tokenServer.URL
	config.ClientID = "test-client"
	config.Store = store
	config.UseDPoP = false

	handler := RefreshHandler(config)

	session, _ := NewSession(uuid.New(), "old-token", "refresh", time.Hour, 24*time.Hour)
	_ = store.Create(context.Background(), session)

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify response
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if resp["success"] != true {
		t.Error("Response should have success: true")
	}
	if resp["expires_at"] == nil {
		t.Error("Response should have expires_at")
	}
}

func TestRefreshHandler_NoSession(t *testing.T) {
	config := DefaultRefreshConfig()
	config.TokenEndpoint = "https://auth.example.com/token"
	config.ClientID = "test-client"

	handler := RefreshHandler(config)

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestRefreshHandler_MethodNotAllowed(t *testing.T) {
	config := DefaultRefreshConfig()
	config.TokenEndpoint = "https://auth.example.com/token"
	config.ClientID = "test-client"

	handler := RefreshHandler(config)

	req := httptest.NewRequest("GET", "/auth/refresh", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestRefreshHandler_ExpiredRefreshToken(t *testing.T) {
	config := DefaultRefreshConfig()
	config.TokenEndpoint = "https://auth.example.com/token"
	config.ClientID = "test-client"
	config.CookieManager = NewCookieManager(DefaultCookieConfig())

	handler := RefreshHandler(config)

	// Create session with expired refresh token
	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, -time.Hour)
	session.RefreshTokenExpiresAt = time.Now().Add(-time.Hour)

	req := httptest.NewRequest("POST", "/auth/refresh", nil)
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}

	// Should clear the session cookie
	cookies := rr.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == DefaultCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil || sessionCookie.MaxAge != -1 {
		t.Error("Should clear session cookie on expired refresh token")
	}
}

func TestAutoRefreshMiddleware(t *testing.T) {
	config := DefaultRefreshConfig()
	config.TokenEndpoint = "https://auth.example.com/token"
	config.ClientID = "test-client"

	middleware, err := AutoRefreshMiddleware(config)
	if err != nil {
		t.Fatalf("AutoRefreshMiddleware() error: %v", err)
	}

	if middleware == nil {
		t.Error("AutoRefreshMiddleware() returned nil")
	}
}

func TestAutoRefreshMiddleware_NoTokenEndpoint(t *testing.T) {
	config := DefaultRefreshConfig()
	config.ClientID = "test-client"

	_, err := AutoRefreshMiddleware(config)
	if err == nil {
		t.Error("AutoRefreshMiddleware() should error without token endpoint")
	}
}

func TestRefresher_OnRefreshSuccess(t *testing.T) {
	successCalled := false
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Test mock OAuth token response
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: "new-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer tokenServer.Close()

	config := DefaultRefreshConfig()
	config.TokenEndpoint = tokenServer.URL
	config.ClientID = "test-client"
	config.UseDPoP = false
	config.OnRefreshSuccess = func(ctx context.Context, session *Session) {
		successCalled = true
	}

	refresher, _ := NewRefresher(config)

	session, _ := NewSession(uuid.New(), "old-token", "refresh", time.Hour, 24*time.Hour)

	err := refresher.RefreshSession(context.Background(), session)
	if err != nil {
		t.Fatalf("RefreshSession() error: %v", err)
	}

	if !successCalled {
		t.Error("OnRefreshSuccess should be called")
	}
}

func TestParseDefaultTokenResponse(t *testing.T) {
	body := []byte(`{"access_token":"token","token_type":"Bearer","expires_in":3600}`)

	resp, err := parseDefaultTokenResponse(body)
	if err != nil {
		t.Fatalf("parseDefaultTokenResponse() error: %v", err)
	}

	if resp.AccessToken != "token" {
		t.Errorf("AccessToken = %s, want token", resp.AccessToken)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", resp.ExpiresIn)
	}
}

func TestParseDefaultTokenResponse_MissingAccessToken(t *testing.T) {
	body := []byte(`{"token_type":"Bearer","expires_in":3600}`)

	_, err := parseDefaultTokenResponse(body)
	if err == nil {
		t.Error("parseDefaultTokenResponse() should error for missing access_token")
	}
}

func TestParseDefaultTokenResponse_InvalidJSON(t *testing.T) {
	body := []byte(`not json`)

	_, err := parseDefaultTokenResponse(body)
	if err == nil {
		t.Error("parseDefaultTokenResponse() should error for invalid JSON")
	}
}

// Concurrent requests for one session must spend its refresh token once: a
// second use of a rotated token looks like theft and revokes the session.
func TestRefresher_RefreshSession_ConcurrentRequestsRefreshOnce(t *testing.T) {
	var calls atomic.Int64
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		time.Sleep(20 * time.Millisecond) // widen the window for the others to pile up
		w.Header().Set("Content-Type", "application/json")
		//nolint:gosec // G117: Test mock OAuth token response
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  fmt.Sprintf("access-%d", n),
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: fmt.Sprintf("refresh-%d", n),
		})
	}))
	defer tokenServer.Close()

	store := NewMemoryStore(StoreConfig{})
	defer func() { _ = store.Close() }()

	config := DefaultRefreshConfig()
	config.TokenEndpoint = tokenServer.URL
	config.ClientID = "test-client"
	config.Store = store
	config.UseDPoP = false
	refresher, err := NewRefresher(config)
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}

	stored, err := NewSession(uuid.New(), "old-access", "old-refresh", time.Minute, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := store.Create(context.Background(), stored); err != nil {
		t.Fatalf("store.Create: %v", err)
	}

	const requests = 10
	var wg sync.WaitGroup
	results := make([]*Session, requests)
	errs := make([]error, requests)
	for i := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each request works on its own copy, as loaded by the session middleware.
			cp := *stored
			results[i] = &cp
			errs[i] = refresher.RefreshSession(context.Background(), &cp)
		}()
	}
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Errorf("token endpoint called %d times, want 1", got)
	}
	for i := range requests {
		if errs[i] != nil {
			t.Errorf("request %d: %v", i, errs[i])
			continue
		}
		if results[i].RefreshToken != "refresh-1" {
			t.Errorf("request %d holds refresh token %q, want refresh-1", i, results[i].RefreshToken)
		}
	}
}
