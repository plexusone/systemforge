package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/systemauth"
)

// TestTokenEndpointBodyLimit verifies that the token endpoint limits the
// body before it parses it: a body over systemauth.MaxTokenRequestBody is
// refused as too large.
func TestTokenEndpointBodyLimit(t *testing.T) {
	f := newFlow(t)
	api, err := NewAPI(f.p, WithAnyClient())
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {f.clientID}, "code": {"unknown"}}.Encode()

	post := func(body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		api.ServeHTTP(w, req)
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("token response not JSON (%d): %s", w.Code, w.Body.String())
		}
		return w.Code, out
	}

	if _, body := post(form); strings.Contains(str(body["error_description"]), "too large") {
		t.Fatalf("small body refused as too large: %v", body)
	}
	code, body := post(form + "&pad=" + strings.Repeat("a", systemauth.MaxTokenRequestBody))
	if code != http.StatusBadRequest || body["error"] != "invalid_request" || !strings.Contains(str(body["error_description"]), "too large") {
		t.Errorf("oversized body: %d %v", code, body)
	}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
