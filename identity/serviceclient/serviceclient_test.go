package serviceclient

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/grokify/goauth/dpop"

	"github.com/plexusone/systemforge/identity/relyingparty"
)

// fakeAuth is a token endpoint that checks the assertion and the proof,
// asks for a nonce first, and an API that checks the token and the proof.
type fakeAuth struct {
	t         *testing.T
	srv       *httptest.Server
	pub       crypto.PublicKey
	ttl       int64
	exchanges atomic.Int32
	apiCalls  atomic.Int32
	mu        sync.Mutex
	issued    map[string]string // token -> proof key thumbprint
}

const testNonce = "n-1"

func newFake(t *testing.T, pub crypto.PublicKey) *fakeAuth {
	f := &fakeAuth{t: t, pub: pub, ttl: 3600, issued: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", f.handleToken)
	mux.HandleFunc("/api", f.handleAPI)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAuth) metadata() *relyingparty.Metadata {
	return &relyingparty.Metadata{Issuer: f.srv.URL, TokenEndpoint: f.srv.URL + "/token"}
}

func (f *fakeAuth) fail(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": code}); err != nil {
		f.t.Error(err)
	}
}

func (f *fakeAuth) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != GrantType {
		f.fail(w, "unsupported_grant_type")
		return
	}
	claims := gojwt.RegisteredClaims{}
	tok, err := gojwt.ParseWithClaims(r.PostForm.Get("assertion"), &claims, func(*gojwt.Token) (any, error) { return f.pub, nil },
		gojwt.WithAudience(f.srv.URL+"/token"), gojwt.WithIssuedAt(), gojwt.WithExpirationRequired())
	if err != nil || claims.Issuer != "sa_test" || claims.Subject != "sa_test" || claims.ID == "" || tok.Header["kid"] != "key-1" ||
		claims.ExpiresAt.Sub(claims.IssuedAt.Time) > 5*time.Minute {
		f.fail(w, "invalid_grant")
		return
	}
	proof, err := dpop.ParseProof(r.Header.Get(dpop.HeaderDPoP))
	if err != nil || proof.Claims.HTTPMethod != http.MethodPost || proof.Claims.HTTPURI != f.srv.URL+"/token" {
		f.fail(w, "invalid_dpop_proof")
		return
	}
	if proof.Claims.Nonce != testNonce {
		w.Header().Set(nonceHeader, testNonce)
		f.fail(w, "use_dpop_nonce")
		return
	}
	n := f.exchanges.Add(1)
	access := fmt.Sprintf("tok-%d", n)
	f.mu.Lock()
	f.issued[access] = proof.Thumbprint
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"access_token": access, "token_type": "DPoP", "expires_in": f.ttl}); err != nil {
		f.t.Error(err)
	}
}

func (f *fakeAuth) handleAPI(w http.ResponseWriter, r *http.Request) {
	f.apiCalls.Add(1)
	access, ok := strings.CutPrefix(r.Header.Get("Authorization"), "DPoP ")
	proof, err := dpop.ParseProof(r.Header.Get(dpop.HeaderDPoP))
	f.mu.Lock()
	jkt, issued := f.issued[access]
	f.mu.Unlock()
	if !ok || err != nil || !issued || proof.Thumbprint != jkt || proof.Claims.HTTPURI != f.srv.URL+"/api" ||
		proof.Claims.AccessTokenHash != dpop.ComputeAccessTokenHash(access) {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if _, err := fmt.Fprint(w, "ok"); err != nil {
		f.t.Error(err)
	}
}

func (f *fakeAuth) client(t *testing.T, key crypto.Signer) *Client {
	t.Helper()
	c, err := New(t.Context(), Config{Issuer: f.srv.URL, Account: "sa_test", KeyID: "key-1", PrivateKey: key, Metadata: f.metadata()})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func get(t *testing.T, hc *http.Client, url string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode
}

func keys(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.Signer{"P-256": ec, "RSA": rk, "Ed25519": ed}
}

func TestCallAPI(t *testing.T) {
	for name, key := range keys(t) {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, key.Public())
			c := f.client(t, key)
			hc := c.HTTPClient()
			for range 3 {
				if code := get(t, hc, f.srv.URL+"/api"); code != http.StatusOK {
					t.Fatalf("API call: %d", code)
				}
			}
			if n := f.exchanges.Load(); n != 1 {
				t.Errorf("exchanges: %d, want one token reused", n)
			}
			// A P-256 assertion key signs the proofs too.
			if ec, ok := key.(*ecdsa.PrivateKey); ok {
				tp, err := dpop.ComputeThumbprint(&ec.PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				if c.proofKey.Thumbprint != tp {
					t.Error("P-256 key not used for proofs")
				}
			}
		})
	}
}

func TestConcurrentRequestsShareOneExchange(t *testing.T) {
	key := keys(t)["P-256"]
	f := newFake(t, key.Public())
	hc := f.client(t, key).HTTPClient()
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if code := get(t, hc, f.srv.URL+"/api"); code != http.StatusOK {
				t.Errorf("API call: %d", code)
			}
		})
	}
	wg.Wait()
	if n := f.exchanges.Load(); n != 1 {
		t.Errorf("exchanges: %d", n)
	}
}

func TestRenewal(t *testing.T) {
	key := keys(t)["P-256"]
	f := newFake(t, key.Public())
	c := f.client(t, key)
	first, err := c.Token(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// Within a minute of expiry, a new assertion is exchanged.
	c.mu.Lock()
	c.expiry = time.Now().Add(30 * time.Second)
	c.mu.Unlock()
	second, err := c.Token(t.Context())
	if err != nil || second == first {
		t.Fatalf("renewal: %q %q %v", first, second, err)
	}
	// A token the API refuses is replaced and the request retried once.
	f.mu.Lock()
	delete(f.issued, second)
	f.mu.Unlock()
	if code := get(t, c.HTTPClient(), f.srv.URL+"/api"); code != http.StatusOK {
		t.Errorf("after a refused token: %d", code)
	}
	if n := f.exchanges.Load(); n != 3 {
		t.Errorf("exchanges: %d", n)
	}
}

func TestRefusals(t *testing.T) {
	key := keys(t)["P-256"]
	f := newFake(t, key.Public())
	// Signed by a key SystemAuth does not have.
	other := keys(t)["P-256"]
	if _, err := f.client(t, other).Token(t.Context()); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("wrong key: %v", err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: a key the client must refuse
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]crypto.Signer{"RSA 1024": small, "P-384": p384} {
		if _, err := New(t.Context(), Config{Issuer: f.srv.URL, Account: "a", KeyID: "k", PrivateKey: k, Metadata: f.metadata()}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := New(t.Context(), Config{Issuer: f.srv.URL, PrivateKey: key}); err == nil {
		t.Error("missing account accepted")
	}
}

func TestLoadPrivateKey(t *testing.T) {
	dir := t.TempDir()
	for name, key := range keys(t) {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".pem")
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPrivateKey(path); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if isWindows() {
			continue
		}
		if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: a file the client must refuse
			t.Fatal(err)
		}
		if _, err := LoadPrivateKey(path); err == nil {
			t.Errorf("%s readable by others accepted", name)
		}
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})); err != nil {
		t.Errorf("PKCS #1: %v", err)
	}
	if _, err := ParsePrivateKey([]byte("nope")); err == nil {
		t.Error("garbage accepted")
	}
}
