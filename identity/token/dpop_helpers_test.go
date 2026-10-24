package token

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grokify/goauth/dpop"

	"github.com/plexusone/systemforge/identity/dpopproof"
	"github.com/plexusone/systemforge/session/middleware"
)

const testTokenURL = "https://auth.example.com/token" //nolint:gosec // G101: a URL, not a credential

func newKey(t *testing.T) *dpop.KeyPair {
	t.Helper()
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

// verifiedProof returns a proof by kp that a Checker verified, as a token
// endpoint would before issuing tokens.
func verifiedProof(t *testing.T, kp *dpop.KeyPair) *dpopproof.Proof {
	t.Helper()
	checker, err := dpopproof.NewChecker(dpopproof.Config{ReplayCache: middleware.NewMemoryReplayCache()})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dpop.CreateProof(kp, http.MethodPost, testTokenURL)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, testTokenURL, nil)
	r.Header.Set("DPoP", proof)
	p, err := checker.Check(r.Context(), r, dpopproof.Target{Method: http.MethodPost, URI: testTokenURL})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
