package relyingparty

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBearerMiddlewareChecksOriginForCookieSessions verifies that a
// request authenticated by the session cookie must prove it was sent by
// an allowed origin when it changes state, as RequireSession requires.
func TestBearerMiddlewareChecksOriginForCookieSessions(t *testing.T) {
	h := newHarness(t)
	cookie := h.sessionCookie()
	reached := 0
	api := BearerMiddleware(BearerConfig{Principals: h.store, Sessions: h.bff})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached++
			w.WriteHeader(http.StatusNoContent)
		}))
	send := func(method string, mod func(*http.Request)) int {
		req := httptest.NewRequest(method, "/api/things", strings.NewReader("{}"))
		req.AddCookie(cookie)
		mod(req)
		w := httptest.NewRecorder()
		api.ServeHTTP(w, req)
		return w.Code
	}
	fromApp := func(r *http.Request) {
		r.Header.Set("Origin", testAppURL)
		r.Header.Set("Content-Type", "application/json")
	}

	if code := send(http.MethodGet, func(*http.Request) {}); code != http.StatusNoContent {
		t.Errorf("safe request with the cookie: %d", code)
	}
	if code := send(http.MethodPost, fromApp); code != http.StatusNoContent {
		t.Errorf("same-origin POST: %d", code)
	}
	before := reached
	for name, mod := range map[string]func(*http.Request){
		"foreign origin": func(r *http.Request) {
			r.Header.Set("Origin", "https://evil.example")
			r.Header.Set("Content-Type", "application/json")
		},
		"form content type": func(r *http.Request) {
			r.Header.Set("Origin", testAppURL)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		},
		"no content type": func(r *http.Request) { r.Header.Set("Origin", testAppURL) },
	} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			if code := send(method, mod); code != http.StatusForbidden {
				t.Errorf("%s %s with the cookie: %d, want 403", name, method, code)
			}
		}
	}
	if reached != before {
		t.Errorf("a cross-site request reached the handler %d times", reached-before)
	}
}
