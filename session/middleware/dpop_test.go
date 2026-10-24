package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grokify/goauth/dpop"

	"github.com/plexusone/systemforge/session/jwt"
)

const dpopTestBase = "https://api.example.com"

func dpopFixture(t *testing.T) (*jwt.Service, *dpop.KeyPair, string, string) {
	t.Helper()
	svc, err := jwt.NewService(&jwt.Config{
		Secret:             []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:          "HS256",
		Issuer:             "test-issuer",
		Audience:           []string{"test-app"},
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bound, err := svc.GenerateAccessTokenWithOptions(uuid.New(), "a@example.com", "A", jwt.TokenOptions{DPoPThumbprint: kp.Thumbprint})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := svc.GenerateAccessToken(uuid.New(), "b@example.com", "B")
	if err != nil {
		t.Fatal(err)
	}
	return svc, kp, bound, plain
}

func proofFor(t *testing.T, kp *dpop.KeyPair, method, path, token string) string {
	t.Helper()
	p, err := dpop.CreateProofWithOptions(kp, method, dpopTestBase+path, dpop.ProofOptions{AccessToken: token})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func serve(h http.Handler, method, path, auth, proof string) int {
	req := httptest.NewRequest(method, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

// A DPoP-bound token must not work as a plain bearer token.
func TestHTTPAuth_RejectsDPoPBoundBearer(t *testing.T) {
	svc, _, bound, plain := dpopFixture(t)
	for name, h := range map[string]http.Handler{
		"HTTPAuth":            HTTPAuth(svc)(okHandler),
		"HTTPAuthForAudience": HTTPAuthForAudience(svc, "test-app")(okHandler),
	} {
		if code := serve(h, "GET", "/items", "Bearer "+bound, ""); code != http.StatusUnauthorized {
			t.Errorf("%s: bound token as Bearer: status %d, want 401", name, code)
		}
		if code := serve(h, "GET", "/items", "Bearer "+plain, ""); code != http.StatusOK {
			t.Errorf("%s: unbound token: status %d, want 200", name, code)
		}
	}

	var gotClaims bool
	optional := HTTPAuthOptional(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = ClaimsFromContext(r.Context()) != nil
	}))
	serve(optional, "GET", "/items", "Bearer "+bound, "")
	if gotClaims {
		t.Error("HTTPAuthOptional attached claims of a bound token presented as Bearer")
	}
}

func TestDPoPAuth(t *testing.T) {
	svc, kp, bound, plain := dpopFixture(t)
	other, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	mw, err := HTTPAuthDPoP(svc, DPoPConfig{ReplayCache: NewMemoryReplayCache(), BaseURL: dpopTestBase})
	if err != nil {
		t.Fatal(err)
	}
	h := mw(okHandler)

	good := proofFor(t, kp, "GET", "/items", bound)
	if code := serve(h, "GET", "/items", "DPoP "+bound, good); code != http.StatusOK {
		t.Fatalf("valid proof: status %d, want 200", code)
	}
	if code := serve(h, "GET", "/items", "DPoP "+bound, good); code != http.StatusUnauthorized {
		t.Errorf("replayed proof: status %d, want 401", code)
	}

	cases := map[string]struct{ auth, proof, method, path string }{
		"bearer scheme":       {"Bearer " + bound, proofFor(t, kp, "GET", "/items", bound), "GET", "/items"},
		"no proof":            {"DPoP " + bound, "", "GET", "/items"},
		"other key":           {"DPoP " + bound, proofFor(t, other, "GET", "/items", bound), "GET", "/items"},
		"wrong method":        {"DPoP " + bound, proofFor(t, kp, "POST", "/items", bound), "GET", "/items"},
		"wrong path":          {"DPoP " + bound, proofFor(t, kp, "GET", "/other", bound), "GET", "/items"},
		"no ath":              {"DPoP " + bound, proofFor(t, kp, "GET", "/items", ""), "GET", "/items"},
		"unbound with dpop":   {"DPoP " + plain, proofFor(t, kp, "GET", "/items", plain), "GET", "/items"},
		"missing credentials": {"", "", "GET", "/items"},
	}
	for name, c := range cases {
		if code := serve(h, c.method, c.path, c.auth, c.proof); code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, code)
		}
	}

	if code := serve(h, "GET", "/items", "Bearer "+plain, ""); code != http.StatusOK {
		t.Errorf("unbound bearer token: status %d, want 200", code)
	}
}

func TestNewDPoPAuth_RequiresReplayCache(t *testing.T) {
	svc, err := jwt.NewService(&jwt.Config{
		Secret:    []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm: "HS256",
		Issuer:    "test-issuer",
		Audience:  []string{"test-app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDPoPAuth(svc, DPoPConfig{}); !errors.Is(err, ErrReplayCacheRequired) {
		t.Fatalf("err = %v, want ErrReplayCacheRequired", err)
	}
}
