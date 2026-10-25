package systemauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTokenEndpointBodyLimit verifies that the token endpoint limits the
// body before it parses it: an otherwise valid request whose body is over
// MaxTokenRequestBody is refused, and one under it succeeds.
func TestTokenEndpointBodyLimit(t *testing.T) {
	s := newDPoPServiceServer(t, Config{})
	form := serviceForm("legacy", "legacy-secret").Encode()

	post := func(body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("token response not JSON (%d): %s", w.Code, w.Body.String())
		}
		return w.Code, out
	}

	if code, body := post(form + "&pad=" + strings.Repeat("a", 1024)); code != http.StatusOK {
		t.Fatalf("small body: %d %v", code, body)
	}
	code, body := post(form + "&pad=" + strings.Repeat("a", MaxTokenRequestBody))
	if code != http.StatusBadRequest || body["error"] != "invalid_request" || !strings.Contains(str(body["error_description"]), "too large") {
		t.Errorf("oversized body: %d %v", code, body)
	}
}
