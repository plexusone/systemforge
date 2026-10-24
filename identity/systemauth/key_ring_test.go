package systemauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/ory/fosite"
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// rotationServer is one deploy of a rotation: it signs with signing (kid
// signingKID) and verifies also with verify, sharing st with the other
// deploys as a database would be shared.
func rotationServer(t *testing.T, st Storage, signing *rsa.PrivateKey, signingKID string, verify map[string]*rsa.PrivateKey) *Server {
	t.Helper()
	keys := KeyConfig{PrivateKey: signing, KeyID: signingKID}
	for kid, k := range verify {
		keys.VerificationKeys = append(keys.VerificationKeys, VerificationKeyConfig{KeyID: kid, PublicKey: &k.PublicKey})
	}
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Keys:   keys,
		Clients: []ClientConfig{{
			ID: "svc", Type: "confidential", Name: "Service", Secret: "svc-secret",
			GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"},
		}},
		Features: FeatureConfig{EnableJWTAccessTokens: true, RequirePKCE: true},
	}, WithStorage(st))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

func clientCredentialsToken(t *testing.T, s *Server) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret"}, "scope": {"read"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK {
		t.Fatalf("token: %d %s", w.Code, w.Body.String())
	}
	tok, _ := body["access_token"].(string)
	return tok
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

// jwksKIDs returns the kids s publishes.
func jwksKIDs(t *testing.T, s *Server) map[string]bool {
	t.Helper()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(w.Body.Bytes(), &set); err != nil {
		t.Fatalf("jwks: %v", err)
	}
	out := map[string]bool{}
	for _, k := range set.Keys {
		out[k.KeyID] = true
	}
	return out
}

// TestSigningKeyRotation walks a rotation through pre-stage, promotion,
// a rollback and the next rotation: at every step each token issued so
// far verifies and its kid is published, until the key that signed it is
// N-2 and has been dropped.
func TestSigningKeyRotation(t *testing.T) {
	k1, k2, k3 := rsaKey(t), rsaKey(t), rsaKey(t)
	st := NewMemoryStorage()

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
		s := rotationServer(t, st, step.signing, step.kid, step.verify)
		tokens = append(tokens, clientCredentialsToken(t, s))
		published := jwksKIDs(t, s)
		for i, tok := range tokens {
			if _, err := s.introspect(context.Background(), tok, fosite.AccessToken, s.Session("")); err != nil {
				t.Errorf("%s: token %d (kid %s) rejected: %v", step.name, i, tokenKID(t, tok), err)
			}
			if kid := tokenKID(t, tok); !published[kid] {
				t.Errorf("%s: token %d's kid %s is not in the JWKS %v", step.name, i, kid, published)
			}
		}
	}

	// Promoting k3 drops k1, now N-2: its tokens fail, the others verify.
	last := rotationServer(t, st, k3, "k3", map[string]*rsa.PrivateKey{"k2": k2})
	if published := jwksKIDs(t, last); published["k1"] || !published["k2"] || !published["k3"] {
		t.Errorf("next promote JWKS = %v", published)
	}
	for i, tok := range tokens {
		_, err := last.introspect(context.Background(), tok, fosite.AccessToken, last.Session(""))
		switch kid := tokenKID(t, tok); {
		case kid == "k1" && err == nil:
			t.Errorf("next promote: k1 token %d still verifies", i)
		case kid != "k1" && err != nil:
			t.Errorf("next promote: %s token %d rejected: %v", kid, i, err)
		}
	}
}

// TestKeyRingRefusesUnknownKID verifies that a token signed by a key the
// ring does not hold, or naming an unknown kid, is refused.
func TestKeyRingRefusesUnknownKID(t *testing.T) {
	k1, other := rsaKey(t), rsaKey(t)
	ring := newKeyRing(k1, "k1", nil)
	signer := ring.signer()
	sign := func(key *rsa.PrivateKey, kid string) string {
		tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims{"sub": "x"})
		tok.Header["kid"] = kid
		raw, err := tok.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, err := signer.Decode(context.Background(), sign(k1, "k1")); err != nil {
		t.Errorf("own token: %v", err)
	}
	// fosite wraps the key function's error without Unwrap.
	if _, err := signer.Decode(context.Background(), sign(other, "k2")); err == nil || !strings.Contains(err.Error(), errUnknownKeyID.Error()) {
		t.Errorf("unknown kid: err = %v", err)
	}
	if _, err := signer.Decode(context.Background(), sign(other, "k1")); err == nil {
		t.Error("a token signed by another key under the signing kid verified")
	}
}

func TestVerificationKeyConfig(t *testing.T) {
	key := rsaKey(t)
	pkix, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, pemData := range map[string][]byte{
		"pkix":    pemOf(t, "PUBLIC KEY", pkix),
		"pkcs1":   pemOf(t, "RSA PUBLIC KEY", x509.MarshalPKCS1PublicKey(&key.PublicKey)),
		"private": pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)),
	} {
		kc := KeyConfig{VerificationKeys: []VerificationKeyConfig{{PublicKeyPEM: string(pemData)}}}
		if err := kc.LoadVerificationKeys("signing"); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		want, err := KeyThumbprint(key)
		if err != nil {
			t.Fatal(err)
		}
		if got := kc.VerificationKeys[0].KeyID; got != want {
			t.Errorf("%s: default kid %q, want the thumbprint %q", name, got, want)
		}
	}

	for name, kc := range map[string]KeyConfig{
		"no key":          {VerificationKeys: []VerificationKeyConfig{{KeyID: "a"}}},
		"two sources":     {VerificationKeys: []VerificationKeyConfig{{KeyID: "a", PublicKey: &key.PublicKey, PublicKeyFile: "x.pem"}}},
		"signing kid":     {VerificationKeys: []VerificationKeyConfig{{KeyID: "signing", PublicKey: &key.PublicKey}}},
		"duplicate kid":   {VerificationKeys: []VerificationKeyConfig{{KeyID: "a", PublicKey: &key.PublicKey}, {KeyID: "a", PublicKey: &key.PublicKey}}},
		"not a key":       {VerificationKeys: []VerificationKeyConfig{{PublicKeyPEM: "hello"}}},
		"missing file":    {VerificationKeys: []VerificationKeyConfig{{PublicKeyFile: t.TempDir() + "/missing.pem"}}},
		"public key junk": {VerificationKeys: []VerificationKeyConfig{{PublicKeyPEM: string(pemOf(t, "PUBLIC KEY", []byte{1}))}}},
	} {
		if err := kc.LoadVerificationKeys("signing"); !errors.Is(err, ErrInvalidSigningKey) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
