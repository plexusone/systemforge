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

func newPathTestProxy(t *testing.T, backendURL string) *Proxy {
	t.Helper()
	config := DefaultProxyConfig()
	config.TargetURL = backendURL + "/tenant-a/v1"
	config.StripPrefix = "/api"
	config.UseDPoP = false
	proxy, err := NewProxy(config)
	if err != nil {
		t.Fatalf("NewProxy() error: %v", err)
	}
	return proxy
}

func withTestSession(t *testing.T, req *http.Request) *http.Request {
	t.Helper()
	session, err := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("NewSession() error: %v", err)
	}
	return req.WithContext(context.WithValue(req.Context(), ContextKeySession, session))
}

func TestProxy_Handler_RejectsPathEscapingBase(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream reached with path %q", r.URL.EscapedPath())
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	proxy := newPathTestProxy(t, backend.URL)

	for _, target := range []string{
		"/api/../../tenant-b/v1/secrets",
		"/api/%2e%2e/%2e%2e/tenant-b/v1/secrets",
		"/api/..%2f..%2ftenant-b/v1/secrets",
		"/api/users%2F..%2F..%2Fadmin",
		"/api/users%5c..%5cadmin",
		"/api/./users",
		"/api/users/..",
	} {
		req := withTestSession(t, httptest.NewRequest("GET", target, nil))
		rr := httptest.NewRecorder()
		proxy.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want %d", target, rr.Code, http.StatusBadRequest)
		}
	}
}

func TestProxy_Handler_KeepsPathUnderBase(t *testing.T) {
	var got string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	proxy := newPathTestProxy(t, backend.URL)

	req := withTestSession(t, httptest.NewRequest("GET", "/api/users/a%20b..c", nil))
	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if want := "/tenant-a/v1/users/a%20b..c"; got != want {
		t.Errorf("upstream path = %q, want %q", got, want)
	}
}

func TestProxy_Handler_PathRewriteCannotLeaveBase(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream reached with path %q", r.URL.Path)
	}))
	defer backend.Close()

	config := DefaultProxyConfig()
	config.TargetURL = backend.URL + "/tenant-a"
	config.UseDPoP = false
	config.PathRewrite = func(string) string { return "/../tenant-b" }
	proxy, err := NewProxy(config)
	if err != nil {
		t.Fatalf("NewProxy() error: %v", err)
	}

	req := withTestSession(t, httptest.NewRequest("GET", "/users", nil))
	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestProxy_ProxyRequest_RejectsPathEscapingBase(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream reached with path %q", r.URL.Path)
	}))
	defer backend.Close()
	proxy := newPathTestProxy(t, backend.URL)

	req := withTestSession(t, httptest.NewRequest("GET", "/", nil))
	resp, err := proxy.ProxyRequest(req.Context(), "GET", "/api/../../tenant-b/v1/secrets", nil)
	if resp != nil {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Errorf("closing body: %v", cerr)
		}
	}
	if !errors.Is(err, ErrInvalidProxyPath) {
		t.Fatalf("ProxyRequest() error = %v, want ErrInvalidProxyPath", err)
	}
}
