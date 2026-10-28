package appauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grokify/goauth/dpop"
)

func p256PEM(t *testing.T, sec1 bool) (string, *ecdsa.PrivateKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if sec1 {
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), k
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), k
}

func TestParseDPoPKey(t *testing.T) {
	for _, sec1 := range []bool{false, true} {
		s, k := p256PEM(t, sec1)
		kp, err := ParseDPoPKey(s)
		if err != nil {
			t.Fatalf("sec1=%v: %v", sec1, err)
		}
		want, err := dpop.ComputeThumbprint(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if kp.Thumbprint != want {
			t.Errorf("thumbprint: %s, want %s", kp.Thumbprint, want)
		}
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for name, tc := range map[string]struct{ in, want string }{
		"not PEM":    {"hello", "not a PEM private key"},
		"public key": {string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})), `PEM block "PUBLIC KEY" is not a private key`},
		"garbage":    {string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})), "parsing private key"},
		"RSA":        {rsaPEM, "must be a P-256 (ES256) key"},
	} {
		if _, err := ParseDPoPKey(tc.in); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReadDPoPKeyFile(t *testing.T) {
	s, _ := p256PEM(t, false)
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDPoPKeyFile(path); err != nil {
		t.Fatal(err)
	}
	c := validConfig(t)
	c.DPoPKey, c.DPoPKeyFile = "", path
	if err := c.Validate(DefaultLabels); err != nil {
		t.Errorf("key file: %v", err)
	}
	if _, err := ReadDPoPKeyFile(filepath.Join(t.TempDir(), "missing.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	if _, err := ReadDPoPKeyFile(t.TempDir()); err == nil {
		t.Error("a directory is not a key file")
	}
}
