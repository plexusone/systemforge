package systemauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDPoPResourceBaseURL verifies that a proof for a route behind
// Middleware (as behind BearerAccess) names dpop.resource_base_url plus
// the request path, so a proxy that strips a path prefix can be
// configured with the external URL.
func TestDPoPResourceBaseURL(t *testing.T) {
	const base = "https://example.com/api"
	s := newDPoPServiceServer(t, Config{DPoP: DPoPConfig{ResourceBaseURL: base + "/"}})
	kp := newDPoPKey(t)
	_, body := rawTokenRequest(t, s, serviceForm("svc", "svc-secret"), tokenProof(t, kp))
	at := str(body["access_token"])

	h := s.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	access := func(htu string) int {
		r := httptest.NewRequest(http.MethodGet, "/things", nil)
		r.Header.Set("Authorization", "DPoP "+at)
		r.Header.Set("DPoP", proofFor(t, kp, http.MethodGet, htu, at))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := access(base + "/things"); code != http.StatusOK {
		t.Errorf("external URL: %d", code)
	}
	if code := access(testIssuer + "/things"); code != http.StatusUnauthorized {
		t.Errorf("a proof for the issuer origin with a resource base URL set: %d", code)
	}

	cfg := DefaultConfig(testIssuer)
	for _, bad := range []string{"example.com/api", "https://example.com/api?x=1", "ftp://example.com"} {
		cfg.DPoP.ResourceBaseURL = bad
		if err := cfg.Validate(); err == nil {
			t.Errorf("resource_base_url %q validated", bad)
		}
	}
}
