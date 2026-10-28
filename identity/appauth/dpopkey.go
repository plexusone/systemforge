package appauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/grokify/goauth/dpop"
)

// DPoPKeyCommand generates a key for Config.DPoPKey or Config.DPoPKeyFile.
const DPoPKeyCommand = "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256"

// maxKeyFileSize bounds ReadDPoPKeyFile; a PEM P-256 key is a few hundred
// bytes.
const maxKeyFileSize = 16 << 10

// ParseDPoPKey parses a PEM P-256 private key, PKCS #8 or SEC 1.
func ParseDPoPKey(s string) (*dpop.KeyPair, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("not a PEM private key")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("PEM block %q is not a private key", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("must be a P-256 (ES256) key")
	}
	thumbprint, err := dpop.ComputeThumbprint(&ec.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("computing the key thumbprint: %w", err)
	}
	return &dpop.KeyPair{PrivateKey: ec, Thumbprint: thumbprint}, nil
}

// ReadDPoPKeyFile reads and parses a PEM P-256 private key file.
func ReadDPoPKeyFile(path string) (*dpop.KeyPair, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxKeyFileSize {
		return nil, fmt.Errorf("%s is too large for a key", path)
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the path is the operator's configuration
	if err != nil {
		return nil, err
	}
	return ParseDPoPKey(string(b))
}
