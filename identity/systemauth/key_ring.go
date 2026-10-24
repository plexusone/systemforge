package systemauth

import (
	"context"
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
	"github.com/ory/fosite/token/jwt"
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

// errUnknownKeyID is returned for a token whose kid names no key.
var errUnknownKeyID = errors.New("systemauth: unknown key id")

// keyRing holds SystemAuth's signing key and the keys it verifies with:
// the signing key and every verification key, by kid.
type keyRing struct {
	signing    *rsa.PrivateKey
	signingKID string
	verify     map[string]*rsa.PublicKey
	// order lists the kids in JWKS order, the signing key first.
	order []string
}

func newKeyRing(signing *rsa.PrivateKey, signingKID string, verification []VerificationKeyConfig) *keyRing {
	r := &keyRing{
		signing:    signing,
		signingKID: signingKID,
		verify:     map[string]*rsa.PublicKey{signingKID: &signing.PublicKey},
		order:      []string{signingKID},
	}
	for _, v := range verification {
		r.verify[v.KeyID] = v.PublicKey
		r.order = append(r.order, v.KeyID)
	}
	return r
}

// jwks returns the published key set: the signing key first, then the
// verification keys.
func (r *keyRing) jwks() jose.JSONWebKeySet {
	set := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(r.order))}
	for _, kid := range r.order {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       r.verify[kid],
			KeyID:     kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		})
	}
	return set
}

// keyFunc selects the key that verifies a token by its kid header: the
// signing key's kid or none selects the signing key, a verification key's
// kid selects that key, and any other kid is refused.
func (r *keyRing) keyFunc(t *jwt.Token) (interface{}, error) {
	raw, present := t.Header["kid"]
	if !present {
		return &r.signing.PublicKey, nil
	}
	kid, ok := raw.(string)
	if !ok {
		return nil, fmt.Errorf("%w: kid header is not a string", errUnknownKeyID)
	}
	key, ok := r.verify[kid]
	if !ok {
		return nil, fmt.Errorf("%w %q", errUnknownKeyID, kid)
	}
	return key, nil
}

// signer returns the fosite JWT signer of the ring: it signs with the
// signing key and verifies with the key the token's kid selects.
func (r *keyRing) signer() jwt.Signer {
	return &keyRingSigner{
		ring: r,
		sign: &jwt.DefaultSigner{GetPrivateKey: func(context.Context) (interface{}, error) { return r.signing, nil }},
	}
}

// keyRingSigner is a fosite jwt.Signer over a keyRing.
type keyRingSigner struct {
	ring *keyRing
	sign *jwt.DefaultSigner
}

var _ jwt.Signer = (*keyRingSigner)(nil)

// Generate signs with the signing key.
func (s *keyRingSigner) Generate(ctx context.Context, claims jwt.MapClaims, header jwt.Mapper) (string, string, error) {
	return s.sign.Generate(ctx, claims, header)
}

// Validate verifies token with the key its kid selects and returns its
// signature.
func (s *keyRingSigner) Validate(ctx context.Context, token string) (string, error) {
	if _, err := s.Decode(ctx, token); err != nil {
		return "", err
	}
	return s.sign.GetSignature(ctx, token)
}

// Decode verifies token with the key its kid selects and returns it.
func (s *keyRingSigner) Decode(_ context.Context, token string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(token, jwt.MapClaims{}, s.ring.keyFunc)
}

// GetSignature implements jwt.Signer.
func (s *keyRingSigner) GetSignature(ctx context.Context, token string) (string, error) {
	return s.sign.GetSignature(ctx, token)
}

// Hash implements jwt.Signer.
func (s *keyRingSigner) Hash(ctx context.Context, in []byte) ([]byte, error) {
	return s.sign.Hash(ctx, in)
}

// GetSigningMethodLength implements jwt.Signer.
func (s *keyRingSigner) GetSigningMethodLength(ctx context.Context) int {
	return s.sign.GetSigningMethodLength(ctx)
}
