package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/plexusone/systemforge/identity/systemauth"
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// rotationAPI is one deploy of a rotation over the database of s: it signs
// with signing (kid signingKID) and verifies also with verify.
func rotationAPI(t *testing.T, s *dpopServer, signing *rsa.PrivateKey, signingKID string, verify map[string]*rsa.PrivateKey) *API {
	t.Helper()
	cfg := DefaultConfig(dpopIssuer, []byte("0123456789abcdef0123456789abcdef"))
	cfg.PrivateKey = signing
	cfg.KeyID = signingKID
	cfg.JWTAccessTokens = true
	for kid, k := range verify {
		cfg.VerificationKeys = append(cfg.VerificationKeys, systemauth.VerificationKeyConfig{KeyID: kid, PublicKey: &k.PublicKey})
	}
	p, err := NewProvider(s.db, cfg)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	api, err := NewAPI(p, WithAnyClient())
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	return api
}

func rotationToken(t *testing.T, s *dpopServer, api *API) string {
	t.Helper()
	s.api = api
	w, body := s.token(t, serviceForm("svc"), tokenProof(t, newDPoPKey(t)))
	if w.Code != http.StatusOK {
		t.Fatalf("token: %d %v", w.Code, body)
	}
	return str(body["access_token"])
}

func tokenKID(t *testing.T, tok string) string {
	t.Helper()
	parsed, _, err := gojwt.NewParser().ParseUnverified(tok, gojwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := parsed.Header["kid"].(string)
	return kid
}

func jwksKIDs(t *testing.T, api *API) map[string]bool {
	t.Helper()
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	var set JWKS
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatalf("jwks: %d %v", w.Code, err)
	}
	out := map[string]bool{}
	for _, k := range set.Keys {
		out[k.Kid] = true
	}
	return out
}

// TestSigningKeyRotation walks a rotation through pre-stage, promotion,
// a rollback and the next rotation: at every step each token issued so
// far verifies and its kid is published, until the key that signed it is
// N-2 and has been dropped.
func TestSigningKeyRotation(t *testing.T) {
	s := newDPoPServer(t, nil)
	k1, k2, k3 := rsaKey(t), rsaKey(t), rsaKey(t)

	steps := []struct {
		name    string
		signing *rsa.PrivateKey
		kid     string
		verify  map[string]*rsa.PrivateKey
	}{
		{"steady", k1, "k1", nil},
		{"pre-stage", k1, "k1", map[string]*rsa.PrivateKey{"k2": k2}},
		{"promote", k2, "k2", map[string]*rsa.PrivateKey{"k1": k1}},
		{"roll back", k1, "k1", map[string]*rsa.PrivateKey{"k2": k2}},
		{"promote again", k2, "k2", map[string]*rsa.PrivateKey{"k1": k1}},
		{"next pre-stage", k2, "k2", map[string]*rsa.PrivateKey{"k1": k1, "k3": k3}},
	}
	var tokens []string
	for _, step := range steps {
		api := rotationAPI(t, s, step.signing, step.kid, step.verify)
		tokens = append(tokens, rotationToken(t, s, api))
		published := jwksKIDs(t, api)
		for i, tok := range tokens {
			if _, err := api.provider.introspect(context.Background(), tok); err != nil {
				t.Errorf("%s: token %d (kid %s) rejected: %v", step.name, i, tokenKID(t, tok), err)
			}
			if kid := tokenKID(t, tok); !published[kid] {
				t.Errorf("%s: token %d's kid %s is not in the JWKS %v", step.name, i, kid, published)
			}
		}
	}

	// Promoting k3 drops k1, now N-2: its tokens fail, the others verify.
	last := rotationAPI(t, s, k3, "k3", map[string]*rsa.PrivateKey{"k2": k2})
	if published := jwksKIDs(t, last); published["k1"] || !published["k2"] || !published["k3"] {
		t.Errorf("next promote JWKS = %v", published)
	}
	for i, tok := range tokens {
		_, err := last.provider.introspect(context.Background(), tok)
		switch kid := tokenKID(t, tok); {
		case kid == "k1" && err == nil:
			t.Errorf("next promote: k1 token %d still verifies", i)
		case kid != "k1" && err != nil:
			t.Errorf("next promote: %s token %d rejected: %v", kid, i, err)
		}
	}
}

// TestProviderKeyConfiguration verifies that a verification key may not
// reuse the signing key's kid.
func TestProviderKeyConfiguration(t *testing.T) {
	key := rsaKey(t)
	cfg := DefaultConfig(dpopIssuer, []byte("0123456789abcdef0123456789abcdef"))
	cfg.PrivateKey = key
	cfg.KeyID = "k1"
	cfg.VerificationKeys = []systemauth.VerificationKeyConfig{{KeyID: "k1", PublicKey: &rsaKey(t).PublicKey}}
	if _, err := NewProvider(nil, cfg); !errors.Is(err, systemauth.ErrInvalidSigningKey) {
		t.Errorf("duplicate kid: err = %v", err)
	}
}
