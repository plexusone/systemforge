package dpopproof

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grokify/goauth/dpop"
)

const testURI = "https://auth.example.com/oauth/token"

type replayCache struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (c *replayCache) Use(_ context.Context, key string, _ time.Time) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[key] {
		return true, nil
	}
	c.seen[key] = true
	return false, nil
}

func newChecker(t *testing.T, nonces *Nonces) *Checker {
	t.Helper()
	c, err := NewChecker(Config{ReplayCache: &replayCache{seen: map[string]bool{}}, Nonces: nonces})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func key(t *testing.T) *dpop.KeyPair {
	t.Helper()
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func proof(t *testing.T, kp *dpop.KeyPair, method, uri string, opts dpop.ProofOptions) string {
	t.Helper()
	p, err := dpop.CreateProofWithOptions(kp, method, uri, opts)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func request(proofs ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, testURI, nil)
	for _, p := range proofs {
		r.Header.Add("DPoP", p)
	}
	return r
}

func TestCheck(t *testing.T) {
	c := newChecker(t, nil)
	kp := key(t)
	target := Target{Method: http.MethodPost, URI: testURI}

	p, err := c.Check(t.Context(), request(proof(t, kp, http.MethodPost, testURI, dpop.ProofOptions{})), target)
	if err != nil || p.JKT() != kp.Thumbprint || p.JTI() == "" || p.IssuedAt().IsZero() {
		t.Fatalf("valid proof: %+v, %v", p, err)
	}
	if (*Proof)(nil).JKT() != "" {
		t.Error("a nil proof has a thumbprint")
	}

	replayed := proof(t, kp, http.MethodPost, testURI, dpop.ProofOptions{})
	if _, err := c.Check(t.Context(), request(replayed), target); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Check(t.Context(), request(replayed), target); !errors.Is(err, ErrReplayed) || !errors.Is(err, ErrInvalid) {
		t.Errorf("replay: %v", err)
	}

	if _, err := c.Check(t.Context(), request(), target); !errors.Is(err, ErrMissing) {
		t.Errorf("no proof: %v", err)
	}
	two := request(proof(t, kp, http.MethodPost, testURI, dpop.ProofOptions{}), proof(t, kp, http.MethodPost, testURI, dpop.ProofOptions{}))
	if _, err := c.Check(t.Context(), two, target); !errors.Is(err, ErrInvalid) {
		t.Errorf("two proofs: %v", err)
	}
	for name, p := range map[string]string{
		"wrong htm": proof(t, kp, http.MethodGet, testURI, dpop.ProofOptions{}),
		"wrong htu": proof(t, kp, http.MethodPost, "https://other.example.com/oauth/token", dpop.ProofOptions{}),
		"garbage":   "a.b.c",
	} {
		if _, err := c.Check(t.Context(), request(p), target); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCheckAccessTokenHash(t *testing.T) {
	c := newChecker(t, nil)
	kp := key(t)
	target := Target{Method: http.MethodPost, URI: testURI, AccessToken: "at-1"}
	if _, err := c.Check(t.Context(), request(proof(t, kp, http.MethodPost, testURI, dpop.ProofOptions{AccessToken: "at-1"})), target); err != nil {
		t.Errorf("matching ath: %v", err)
	}
	for name, opts := range map[string]dpop.ProofOptions{
		"no ath":    {},
		"other ath": {AccessToken: "at-2"},
	} {
		if _, err := c.Check(t.Context(), request(proof(t, kp, http.MethodPost, testURI, opts)), target); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestCheckRefusesPrivateKeyInHeader verifies that a proof whose jwk
// header carries the private key is refused (RFC 9449 §4.3).
func TestCheckRefusesPrivateKeyInHeader(t *testing.T) {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"secret"}}`))
	if err := checkHeader(head + ".e30.sig"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "private key") {
		t.Errorf("private key in jwk: %v", err)
	}
}

func TestNonces(t *testing.T) {
	if _, err := NewNonces([]byte("short"), 0); !errors.Is(err, ErrNonceSecret) {
		t.Errorf("short secret: %v", err)
	}
	nonces, err := NewNonces([]byte(strings.Repeat("k", 32)), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c := newChecker(t, nonces)
	kp := key(t)
	target := Target{Method: http.MethodPost, URI: testURI}

	if _, err := c.Check(t.Context(), request(proof(t, kp, http.MethodPost, testURI, dpop.ProofOptions{})), target); !errors.Is(err, ErrUseNonce) {
		t.Errorf("no nonce: %v", err)
	}
	nonce, err := c.Nonce()
	if err != nil || nonce == "" {
		t.Fatalf("Nonce: %q, %v", nonce, err)
	}
	if _, err := c.Check(t.Context(), request(proof(t, kp, http.MethodPost, testURI, dpop.ProofOptions{Nonce: nonce})), target); err != nil {
		t.Errorf("issued nonce: %v", err)
	}

	// Another secret's nonce, and an expired nonce, are refused.
	foreign, err := NewNonces([]byte(strings.Repeat("o", 32)), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	other, err := foreign.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if err := nonces.validate(t.Context(), other); err == nil {
		t.Error("another secret's nonce accepted")
	}
	nonces.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if err := nonces.validate(t.Context(), nonce); err == nil {
		t.Error("expired nonce accepted")
	}

	// Without nonces, Nonce is empty.
	if n, err := newChecker(t, nil).Nonce(); err != nil || n != "" {
		t.Errorf("Nonce without nonces = %q, %v", n, err)
	}
}

func TestNewCheckerRequiresReplayCache(t *testing.T) {
	if _, err := NewChecker(Config{}); !errors.Is(err, ErrReplayCacheRequired) {
		t.Errorf("err = %v", err)
	}
}
