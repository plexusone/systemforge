package systemauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func pemOf(t *testing.T, typ string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestParseSigningKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSigningKey(pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))); err != nil {
		t.Errorf("PKCS#1: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSigningKey(pemOf(t, "PRIVATE KEY", der)); err != nil {
		t.Errorf("PKCS#8: %v", err)
	}

	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: deliberately weak key to test rejection
	if err != nil {
		t.Fatal(err)
	}
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"not pem":    []byte("hello"),
		"small rsa":  pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(small)),
		"ec":         pemOf(t, "PRIVATE KEY", ecDER),
		"public key": pemOf(t, "PUBLIC KEY", []byte{1}),
	} {
		if _, err := ParseSigningKey(data); !errors.Is(err, ErrInvalidSigningKey) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestSigningKeyFromConfigEnv(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_SIGNING_KEY", string(pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))))
	cfg, err := ParseConfig([]byte("issuer: https://auth.example.com\nkeys:\n  key_id: k-2026\n  private_key_pem: ${TEST_SIGNING_KEY}\n"), FormatYAML)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewEmbedded(*cfg)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if s.KeyID() != "k-2026" || s.PublicKey().N.Cmp(key.N) != 0 {
		t.Errorf("configured key not used: kid %q", s.KeyID())
	}

	both := Config{Issuer: testIssuer, Keys: KeyConfig{PrivateKeyPEM: "x", PrivateKeyFile: "/y"}}
	if _, err := NewEmbedded(both); !errors.Is(err, ErrInvalidSigningKey) {
		t.Errorf("pem+file: %v", err)
	}
}

func TestEphemeralKeyIDIsThumbprint(t *testing.T) {
	s, err := NewEmbedded(Config{Issuer: testIssuer})
	if err != nil {
		t.Fatal(err)
	}
	if s.KeyID() == "" || strings.ContainsAny(s.KeyID(), "+/=") {
		t.Errorf("kid = %q", s.KeyID())
	}
}

func TestHealthEndpoints(t *testing.T) {
	failing := errors.New("down")
	var dbErr error
	s, err := NewEmbedded(Config{Issuer: testIssuer}, WithReadinessCheck("database", func(context.Context) error { return dbErr }))
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		return w
	}
	if w := get(HealthzPath); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"ok"`) {
		t.Errorf("healthz: %d %s", w.Code, w.Body.String())
	}
	if w := get(ReadyzPath); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"database":"ok"`) {
		t.Errorf("readyz: %d %s", w.Code, w.Body.String())
	}
	dbErr = failing
	w := get(ReadyzPath)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"database":"fail"`) || strings.Contains(w.Body.String(), "down") {
		t.Errorf("readyz failing: %d %s", w.Code, w.Body.String())
	}
}
