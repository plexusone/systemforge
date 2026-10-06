package systemauth

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v3"
)

// ErrInvalidSigningKey is returned when a configured signing key cannot be
// loaded.
var ErrInvalidSigningKey = errors.New("systemauth: invalid signing key")

// minRSAKeyBits is the smallest accepted RSA signing key.
const minRSAKeyBits = 2048

// ParseSigningKey parses a PEM-encoded RSA private key (PKCS#1 "RSA PRIVATE
// KEY" or PKCS#8 "PRIVATE KEY") of at least 2048 bits.
func ParseSigningKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrInvalidSigningKey)
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSigningKey, err)
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSigningKey, err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: only RSA keys are supported (RS256), got %T", ErrInvalidSigningKey, k)
		}
		key = rk
	default:
		return nil, fmt.Errorf("%w: unsupported PEM block %q", ErrInvalidSigningKey, block.Type)
	}
	if key.N.BitLen() < minRSAKeyBits {
		return nil, fmt.Errorf("%w: RSA key is %d bits, need at least %d", ErrInvalidSigningKey, key.N.BitLen(), minRSAKeyBits)
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSigningKey, err)
	}
	return key, nil
}

// HasSigningKey reports whether the configuration supplies a signing key
// (programmatically, as PEM, or as a file).
func (k *KeyConfig) HasSigningKey() bool {
	return k.PrivateKey != nil || strings.TrimSpace(k.PrivateKeyPEM) != "" || k.PrivateKeyFile != ""
}

// LoadSigningKey resolves PrivateKeyPEM or PrivateKeyFile into PrivateKey.
// It is a no-op when PrivateKey is already set or no key is configured.
func (k *KeyConfig) LoadSigningKey() error {
	if k.PrivateKey != nil {
		return nil
	}
	pemData := strings.TrimSpace(k.PrivateKeyPEM)
	switch {
	case pemData != "" && k.PrivateKeyFile != "":
		return fmt.Errorf("%w: set only one of keys.private_key_pem and keys.private_key_file", ErrInvalidSigningKey)
	case pemData != "":
		key, err := ParseSigningKey([]byte(pemData))
		if err != nil {
			return err
		}
		k.PrivateKey = key
	case k.PrivateKeyFile != "":
		//nolint:gosec // G304: the key path is operator configuration
		data, err := os.ReadFile(k.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("%w: reading %s: %v", ErrInvalidSigningKey, k.PrivateKeyFile, err)
		}
		key, err := ParseSigningKey(data)
		if err != nil {
			return fmt.Errorf("%s: %w", k.PrivateKeyFile, err)
		}
		k.PrivateKey = key
	}
	return nil
}

// KeyThumbprint returns the RFC 7638 SHA-256 thumbprint of the key's public
// part, base64url-encoded. SystemAuth uses it as the default key ID, so a
// new key automatically gets a new "kid".
func KeyThumbprint(key *rsa.PrivateKey) (string, error) {
	jwk := jose.JSONWebKey{Key: &key.PublicKey}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: thumbprint: %v", ErrInvalidSigningKey, err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}
