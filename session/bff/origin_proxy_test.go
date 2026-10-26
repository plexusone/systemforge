package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Proxied GETs carry the user's token, so a cross-site GET must not reach
// the upstream even though GET skips the state-changing origin check.
func TestHandlerProxy_CrossSiteGETRejected(t *testing.T) {
	upstreamCalls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	store := NewMemoryStore(DefaultStoreConfig())
	h, err := NewHandler(HandlerConfig{
		Store:          store,
		AllowedOrigins: []string{"https://app.example.com"},
		ProxyConfig:    ProxyConfig{TargetURL: backend.URL, StripPrefix: "/api"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("closing handler: %v", err)
		}
	})
	sess, err := NewSession(uuid.New(), "at", "rt", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	router := h.Router()

	tests := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"cross-site navigation", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"same-site subdomain", map[string]string{"Sec-Fetch-Site": "same-site"}, http.StatusForbidden},
		{"foreign origin", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"foreign referer, no fetch metadata", map[string]string{"Referer": "https://evil.example/page"}, http.StatusForbidden},
		{"same-origin fetch", map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusOK},
		{"allowed CORS origin", map[string]string{"Origin": "https://app.example.com", "Sec-Fetch-Site": "same-site"}, http.StatusOK},
		{"non-browser client", nil, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := upstreamCalls
			req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			req.AddCookie(sessionCookie(h.CookieManager().Config().Name, sess.ID))
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Errorf("status = %d, want %d", rr.Code, tt.want)
			}
			if tt.want == http.StatusForbidden && upstreamCalls != before {
				t.Error("rejected request reached the upstream")
			}
		})
	}
}
