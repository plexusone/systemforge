package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type failingReplayCache struct{}

func (failingReplayCache) Use(context.Context, string, time.Time) (bool, error) {
	return false, errors.New("dial tcp 10.0.0.9:6379: connection refused")
}

func serveBody(h http.Handler, auth, proof string) (int, string) {
	req := httptest.NewRequest(http.MethodGet, "/items", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String()
}

// TestAuthFailuresDoNotLeakErrorText expects a replay-cache failure and
// token parser detail to stay out of the 401 body.
func TestAuthFailuresDoNotLeakErrorText(t *testing.T) {
	svc, kp, bound, _ := dpopFixture(t)
	mw, err := HTTPAuth(svc, DPoPConfig{ReplayCache: failingReplayCache{}, BaseURL: dpopTestBase})
	if err != nil {
		t.Fatal(err)
	}
	code, body := serveBody(mw(okHandler), "DPoP "+bound, proofFor(t, kp, "GET", "/items", bound))
	if code != http.StatusUnauthorized || strings.Contains(body, "10.0.0.9") || !strings.Contains(body, "authentication failed") {
		t.Errorf("replay cache failure: %d %s", code, body)
	}

	// A malformed token's parser error is reduced to "invalid token".
	for name, h := range map[string]http.Handler{
		"dpop":   mw(okHandler),
		"bearer": HTTPAuthBearer(svc)(okHandler),
	} {
		code, body := serveBody(h, "Bearer not.a.jwt", "")
		if code != http.StatusUnauthorized || !strings.Contains(body, `"message":"invalid token"`) {
			t.Errorf("%s: malformed token: %d %s", name, code, body)
		}
	}
}
