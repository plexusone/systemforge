package bff

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func proxyHeadersSeen(t *testing.T, config ProxyConfig, set map[string]string) http.Header {
	t.Helper()
	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	config.TargetURL = backend.URL
	config.UseDPoP = false
	proxy, err := NewProxy(config)
	if err != nil {
		t.Fatalf("NewProxy() error: %v", err)
	}

	req := httptest.NewRequest("POST", "/users", strings.NewReader(`{}`))
	for k, v := range set {
		req.Header.Set(k, v)
	}
	req = withTestSession(t, req)

	rr := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	return got
}

func TestProxy_Handler_HeadersToForwardIsAllowList(t *testing.T) {
	config := DefaultProxyConfig()
	config.HeadersToForward = []string{"accept"}
	got := proxyHeadersSeen(t, config, map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
		"X-Custom":     "dropped",
	})

	if got.Get("Accept") != "application/json" {
		t.Errorf("Accept = %q, want it forwarded", got.Get("Accept"))
	}
	if got.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want it forwarded", got.Get("Content-Type"))
	}
	if v := got.Get("X-Custom"); v != "" {
		t.Errorf("X-Custom forwarded despite allow-list: %q", v)
	}
	if got.Get("Authorization") != "Bearer token" {
		t.Errorf("Authorization = %q, want the session's token", got.Get("Authorization"))
	}
}

func TestProxy_Handler_StripsClientIdentityHeaders(t *testing.T) {
	identity := map[string]string{
		"X-App-ID":          "other-app",
		"X-User-Id":         "victim",
		"X-Principal-Id":    "victim",
		"X-Organization-Id": "other-org",
		"X-Org-Id":          "other-org",
		"X-Tenant-Id":       "other-tenant",
		"X-Real-IP":         "10.0.0.1",
		"True-Client-IP":    "10.0.0.1",
		"CF-Connecting-IP":  "10.0.0.1",
		"X-Remote-User":     "admin",
		"X-API-Key":         "attacker-key",
	}

	for name, config := range map[string]ProxyConfig{
		"no allow-list":            DefaultProxyConfig(),
		"allow-list names headers": {HeadersToForward: []string{"X-App-ID", "X-User-Id", "X-Tenant-Id"}},
	} {
		t.Run(name, func(t *testing.T) {
			got := proxyHeadersSeen(t, config, identity)
			for h := range identity {
				if v := got.Get(h); v != "" {
					t.Errorf("%s forwarded upstream: %q", h, v)
				}
			}
		})
	}
}

func TestProxy_Handler_OnRequestRewriteCanSetIdentityHeaders(t *testing.T) {
	config := DefaultProxyConfig()
	config.OnRequestRewrite = func(r *http.Request, s *Session) {
		r.Header.Set("X-User-Id", s.UserID.String())
	}
	got := proxyHeadersSeen(t, config, map[string]string{"X-User-Id": "victim"})
	if v := got.Get("X-User-Id"); v == "" || v == "victim" {
		t.Errorf("X-User-Id = %q, want the session's user ID", v)
	}
}
