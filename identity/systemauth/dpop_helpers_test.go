package systemauth

import (
	"net/http"
	"sync"
	"testing"

	"github.com/grokify/goauth/dpop"
)

// testDPoP is the DPoP key the tests' clients prove possession of.
var testDPoP = sync.OnceValues(dpop.GenerateKeyPair)

func testDPoPKey(t *testing.T) *dpop.KeyPair {
	t.Helper()
	kp, err := testDPoP()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func newDPoPKey(t *testing.T) *dpop.KeyPair {
	t.Helper()
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// proofFor returns a DPoP proof by kp for method and uri, carrying the
// hash of accessToken when it is set.
func proofFor(t *testing.T, kp *dpop.KeyPair, method, uri, accessToken string) string {
	t.Helper()
	proof, err := dpop.CreateProofWithOptions(kp, method, uri, dpop.ProofOptions{AccessToken: accessToken})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// withTokenProof adds a DPoP proof by the test key for the token endpoint
// of testIssuer.
func withTokenProof(t *testing.T, r *http.Request) {
	t.Helper()
	r.Header.Set("DPoP", proofFor(t, testDPoPKey(t), http.MethodPost, testIssuer+"/oauth/token", ""))
}

// withAuth applies decorate to r and returns it.
func withAuth(r *http.Request, decorate func(*http.Request)) *http.Request {
	decorate(r)
	return r
}

// dpopAuth presents token as SystemAuth issues it to the tests' clients:
// with the DPoP scheme and a proof by the test key for the request's
// method and URL at testIssuer.
func dpopAuth(t *testing.T, token string) func(*http.Request) {
	t.Helper()
	return func(r *http.Request) {
		r.Header.Set("Authorization", "DPoP "+token)
		r.Header.Set("DPoP", proofFor(t, testDPoPKey(t), r.Method, testIssuer+r.URL.Path, token))
	}
}
