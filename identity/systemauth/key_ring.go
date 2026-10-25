package systemauth

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v3"
	"github.com/plexusone/systemforge/identity/internal/oauthcore"
)

// ParseVerificationKey parses a PEM-encoded RSA key of at least 2048 bits
// for verification: a public key (PKIX "PUBLIC KEY" or PKCS#1 "RSA PUBLIC
// KEY") or a private key, of which the public part is returned.
func ParseVerificationKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrInvalidSigningKey)
	}
	var pub *rsa.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSigningKey, err)
		}
		rk, ok := k.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%w: only RSA keys are supported (RS256), got %T", ErrInvalidSigningKey, k)
		}
		pub = rk
	case "RSA PUBLIC KEY":
		k, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSigningKey, err)
		}
		pub = k
	default:
		priv, err := ParseSigningKey(pemData)
		if err != nil {
			return nil, err
		}
		return &priv.PublicKey, nil
	}
	if pub.N.BitLen() < minRSAKeyBits {
		return nil, fmt.Errorf("%w: RSA key is %d bits, need at least %d", ErrInvalidSigningKey, pub.N.BitLen(), minRSAKeyBits)
	}
	return pub, nil
}

// load resolves the key into PublicKey and its default KeyID.
func (v *VerificationKeyConfig) load() error {
	pemData := strings.TrimSpace(v.PublicKeyPEM)
	set := 0
	for _, given := range []bool{v.PublicKey != nil, pemData != "", v.PublicKeyFile != ""} {
		if given {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("%w: a verification key needs exactly one of public_key_pem, public_key_file or a programmatic key", ErrInvalidSigningKey)
	}
	switch {
	case pemData != "":
		key, err := ParseVerificationKey([]byte(pemData))
		if err != nil {
			return err
		}
		v.PublicKey = key
	case v.PublicKeyFile != "":
		//nolint:gosec // G304: the key path is operator configuration
		data, err := os.ReadFile(v.PublicKeyFile)
		if err != nil {
			return fmt.Errorf("%w: reading %s: %v", ErrInvalidSigningKey, v.PublicKeyFile, err)
		}
		key, err := ParseVerificationKey(data)
		if err != nil {
			return fmt.Errorf("%s: %w", v.PublicKeyFile, err)
		}
		v.PublicKey = key
	}
	if v.PublicKey.N.BitLen() < minRSAKeyBits {
		return fmt.Errorf("%w: RSA key is %d bits, need at least %d", ErrInvalidSigningKey, v.PublicKey.N.BitLen(), minRSAKeyBits)
	}
	if v.KeyID == "" {
		kid, err := publicKeyThumbprint(v.PublicKey)
		if err != nil {
			return err
		}
		v.KeyID = kid
	}
	return nil
}

// LoadVerificationKeys resolves every VerificationKeys entry into its
// PublicKey and KeyID (the key's thumbprint when none is given), and checks
// that no kid is used twice or is signingKID, the signing key's.
func (k *KeyConfig) LoadVerificationKeys(signingKID string) error {
	seen := map[string]bool{signingKID: true}
	for i := range k.VerificationKeys {
		v := &k.VerificationKeys[i]
		if err := v.load(); err != nil {
			return fmt.Errorf("keys.verification_keys[%d]: %w", i, err)
		}
		if seen[v.KeyID] {
			return fmt.Errorf("%w: keys.verification_keys[%d]: kid %q is already used by another key", ErrInvalidSigningKey, i, v.KeyID)
		}
		seen[v.KeyID] = true
	}
	return nil
}

// publicKeyThumbprint is KeyThumbprint for a public key.
func publicKeyThumbprint(key *rsa.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: key}
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("%w: thumbprint: %v", ErrInvalidSigningKey, err)
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// verificationKeys returns loaded verification keys (see
// KeyConfig.LoadVerificationKeys) for an oauthcore.KeyRing.
func verificationKeys(keys []VerificationKeyConfig) []oauthcore.VerificationKey {
	out := make([]oauthcore.VerificationKey, 0, len(keys))
	for _, v := range keys {
		out = append(out, oauthcore.VerificationKey{KeyID: v.KeyID, PublicKey: v.PublicKey})
	}
	return out
}
