package bff

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewProxy(t *testing.T) {
	config := DefaultProxyConfig()
	config.TargetURL = "https://api.example.com"

	proxy, err := NewProxy(config)
	if err != nil {
		t.Fatalf("NewProxy() error: %v", err)
	}

	if proxy == nil {
		t.Fatal("NewProxy() returned nil")
	}
}

func TestNewProxy_InvalidURL(t *testing.T) {
	config := DefaultProxyConfig()
	config.TargetURL = "://invalid"

	_, err := NewProxy(config)
	if err == nil {
		t.Error("NewProxy() should error for invalid URL")
	}
}

func TestNewProxy_MissingScheme(t *testing.T) {
	config := DefaultProxyConfig()
	config.TargetURL = "api.example.com"

	_, err := NewProxy(config)
	if err == nil {
		t.Error("NewProxy() should error for URL without scheme")
	}
}

func TestDefaultProxyConfig(t *testing.T) {
	config := DefaultProxyConfig()

	if !config.UseDPoP {
		t.Error("UseDPoP = false, want true")
	}
	if config.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", config.Timeout)
	}
	if len(config.HeadersToRemove) == 0 {
		t.Error("HeadersToRemove should not be empty")
	}
}

func TestProxy_Handler_NoSession(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Backend should not be called without session")
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	proxy, _ := NewProxy(config)

	req := httptest.NewRequest("GET", "/api/users", nil)
	rr := httptest.NewRecorder()

	proxy.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestProxy_Handler_ExpiredSession(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Backend should not be called with expired session")
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	proxy, _ := NewProxy(config)

	// Create expired session
	session, _ := NewSession(uuid.New(), "token", "refresh", -time.Hour, time.Hour)
	session.AccessTokenExpiresAt = time.Now().Add(-time.Hour)

	req := httptest.NewRequest("GET", "/api/users", nil)
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestProxy_Handler_WithSession(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	config.UseDPoP = false // Disable DPoP for simpler test
	proxy, _ := NewProxy(config)

	session, _ := NewSession(uuid.New(), "test-access-token", "refresh", time.Hour, time.Hour)

	req := httptest.NewRequest("GET", "/api/users", nil)
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}

	if receivedAuth != "Bearer test-access-token" {
		t.Errorf("Authorization = %s, want Bearer test-access-token", receivedAuth)
	}
}

func TestProxy_Handler_StripPrefix(t *testing.T) {
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	config.UseDPoP = false
	config.StripPrefix = "/api"
	proxy, _ := NewProxy(config)

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)

	req := httptest.NewRequest("GET", "/api/v1/users", nil)
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if receivedPath != "/v1/users" {
		t.Errorf("Path = %s, want /v1/users", receivedPath)
	}
}

func TestProxy_Handler_PathRewrite(t *testing.T) {
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	config.UseDPoP = false
	config.PathRewrite = func(path string) string {
		return "/v2" + path
	}
	proxy, _ := NewProxy(config)

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)

	req := httptest.NewRequest("GET", "/users", nil)
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if receivedPath != "/v2/users" {
		t.Errorf("Path = %s, want /v2/users", receivedPath)
	}
}

func TestProxy_Handler_ForwardsBody(t *testing.T) {
	var receivedBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	config.UseDPoP = false
	proxy, _ := NewProxy(config)

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)

	body := `{"name":"test"}`
	req := httptest.NewRequest("POST", "/api/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if receivedBody != body {
		t.Errorf("Body = %s, want %s", receivedBody, body)
	}
}

func TestProxy_Handler_HeadersRemoved(t *testing.T) {
	var receivedCookie string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCookie = r.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	config.UseDPoP = false
	proxy, _ := NewProxy(config)

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Cookie", "session=secret")
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if receivedCookie != "" {
		t.Errorf("Cookie header should be removed, got %s", receivedCookie)
	}
}

func TestProxy_Handler_ResponseHeadersRemoved(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "backend=value")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	config.UseDPoP = false
	proxy, _ := NewProxy(config)

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)

	req := httptest.NewRequest("GET", "/api/users", nil)
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if rr.Header().Get("Set-Cookie") != "" {
		t.Error("Set-Cookie header should be removed from response")
	}
}

func TestProxy_Handler_CustomErrorHandler(t *testing.T) {
	customErrorCalled := false
	config := DefaultProxyConfig()
	config.TargetURL = "https://api.example.com"
	config.OnError = func(w http.ResponseWriter, r *http.Request, err error) {
		customErrorCalled = true
		http.Error(w, "Custom error", http.StatusTeapot)
	}
	proxy, _ := NewProxy(config)

	req := httptest.NewRequest("GET", "/api/users", nil)
	rr := httptest.NewRecorder()

	proxy.Handler().ServeHTTP(rr, req)

	if !customErrorCalled {
		t.Error("Custom error handler should be called")
	}
	if rr.Code != http.StatusTeapot {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusTeapot)
	}
}

func TestProxy_Handler_OnRequestRewrite(t *testing.T) {
	rewriteCalled := false
	var customHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		customHeader = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	config.UseDPoP = false
	config.OnRequestRewrite = func(r *http.Request, session *Session) {
		rewriteCalled = true
		r.Header.Set("X-Custom", "custom-value")
	}
	proxy, _ := NewProxy(config)

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)

	req := httptest.NewRequest("GET", "/api/users", nil)
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if !rewriteCalled {
		t.Error("OnRequestRewrite should be called")
	}
	if customHeader != "custom-value" {
		t.Errorf("X-Custom = %s, want custom-value", customHeader)
	}
}

func TestProxy_Handler_TargetBasePath(t *testing.T) {
	var receivedPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL + "/v1/api"
	config.UseDPoP = false
	proxy, _ := NewProxy(config)

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)

	req := httptest.NewRequest("GET", "/users", nil)
	ctx := context.WithValue(req.Context(), ContextKeySession, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if receivedPath != "/v1/api/users" {
		t.Errorf("Path = %s, want /v1/api/users", receivedPath)
	}
}

func TestProxy_ProxyRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":123}`))
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	config.UseDPoP = false
	proxy, _ := NewProxy(config)

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)
	ctx := context.WithValue(context.Background(), ContextKeySession, session)

	resp, err := proxy.ProxyRequest(ctx, "GET", "/users/123", nil)
	if err != nil {
		t.Fatalf("ProxyRequest() error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"id":123}` {
		t.Errorf("Body = %s, want {\"id\":123}", string(body))
	}
}

func TestProxy_ProxyRequest_NoSession(t *testing.T) {
	config := DefaultProxyConfig()
	config.TargetURL = "https://api.example.com"
	proxy, _ := NewProxy(config)

	_, err := proxy.ProxyRequest(context.Background(), "GET", "/users", nil)
	if err != ErrSessionNotFound {
		t.Errorf("ProxyRequest() error = %v, want ErrSessionNotFound", err)
	}
}

func TestProxy_ProxyRequest_ExpiredSession(t *testing.T) {
	config := DefaultProxyConfig()
	config.TargetURL = "https://api.example.com"
	proxy, _ := NewProxy(config)

	session, _ := NewSession(uuid.New(), "token", "refresh", -time.Hour, time.Hour)
	session.AccessTokenExpiresAt = time.Now().Add(-time.Hour)
	ctx := context.WithValue(context.Background(), ContextKeySession, session)

	_, err := proxy.ProxyRequest(ctx, "GET", "/users", nil)
	if err != ErrSessionExpired {
		t.Errorf("ProxyRequest() error = %v, want ErrSessionExpired", err)
	}
}

func TestSimpleProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	handler, err := SimpleProxy(backend.URL)
	if err != nil {
		t.Fatalf("SimpleProxy() error: %v", err)
	}

	if handler == nil {
		t.Error("SimpleProxy() returned nil handler")
	}
}

func TestSimpleProxy_InvalidURL(t *testing.T) {
	_, err := SimpleProxy("://invalid")
	if err == nil {
		t.Error("SimpleProxy() should error for invalid URL")
	}
}

func TestAPIProxyMiddleware(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	middleware, err := APIProxyMiddleware(backend.URL)
	if err != nil {
		t.Fatalf("APIProxyMiddleware() error: %v", err)
	}

	if middleware == nil {
		t.Error("APIProxyMiddleware() returned nil")
	}
}

func TestAPIProxyMiddleware_InvalidURL(t *testing.T) {
	_, err := APIProxyMiddleware("://invalid")
	if err == nil {
		t.Error("APIProxyMiddleware() should error for invalid URL")
	}
}

func TestSingleJoiningSlash(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"", "", "/"},
		{"/", "", "/"},
		{"", "/", "/"},
		{"/", "/", "/"},
		{"/a", "b", "/a/b"},
		{"/a/", "b", "/a/b"},
		{"/a", "/b", "/a/b"},
		{"/a/", "/b", "/a/b"},
		{"/api", "/users", "/api/users"},
	}

	for _, tt := range tests {
		got := singleJoiningSlash(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("singleJoiningSlash(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestRemoveHopByHopHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive, x-custom")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Authorization", "Basic xxx")
	h.Set("X-Custom", "value")
	h.Set("Content-Type", "application/json")

	removeHopByHopHeaders(h)

	if h.Get("Connection") != "" {
		t.Error("Connection header should be removed")
	}
	if h.Get("Keep-Alive") != "" {
		t.Error("Keep-Alive header should be removed")
	}
	if h.Get("Proxy-Authorization") != "" {
		t.Error("Proxy-Authorization header should be removed")
	}
	if h.Get("X-Custom") != "" {
		t.Error("X-Custom header should be removed (listed in Connection)")
	}
	if h.Get("Content-Type") != "application/json" {
		t.Error("Content-Type header should be preserved")
	}
}

func TestProxy_Handler_MethodPreserved(t *testing.T) {
	var receivedMethod string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	config.UseDPoP = false
	proxy, _ := NewProxy(config)

	session, _ := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)

	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE"}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/users", nil)
		ctx := context.WithValue(req.Context(), ContextKeySession, session)
		req = req.WithContext(ctx)

		rr := httptest.NewRecorder()
		proxy.Handler().ServeHTTP(rr, req)

		if receivedMethod != method {
			t.Errorf("Method = %s, want %s", receivedMethod, method)
		}
	}
}

// A ProxyConfig built by hand has no HeadersToRemove; the browser's cookie and
// any client-supplied Authorization or DPoP header must still not reach the
// upstream.
func TestProxy_Handler_StripsBrowserCredentialsWithoutConfig(t *testing.T) {
	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	proxy, err := NewProxy(ProxyConfig{TargetURL: backend.URL})
	if err != nil {
		t.Fatalf("NewProxy() error: %v", err)
	}
	session, err := NewSession(uuid.New(), "real-token", "refresh", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Cookie", "sf_session=secret")
	req.Header.Set("Authorization", "Bearer attacker-token")
	req.Header.Set("DPoP", "forged-proof")
	req = req.WithContext(context.WithValue(req.Context(), ContextKeySession, session))

	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want %d", rr.Code, http.StatusOK)
	}
	if c := got.Get("Cookie"); c != "" {
		t.Errorf("Cookie forwarded upstream: %q", c)
	}
	if d := got.Get("DPoP"); d != "" {
		t.Errorf("client DPoP header forwarded upstream: %q", d)
	}
	if a := got.Get("Authorization"); a != "Bearer real-token" {
		t.Errorf("Authorization = %q, want the session's token", a)
	}
}
