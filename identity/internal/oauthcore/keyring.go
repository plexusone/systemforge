package oauthcore

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite/token/jwt"
)

// errUnknownKeyID is returned for a token whose kid names no key.
var errUnknownKeyID = errors.New("oauthcore: unknown key id")

// VerificationKey is a key tokens are verified with besides the signing
// key: the previous signing key N-1 after a rotation, or a pre-staged next
// key.
type VerificationKey struct {
	KeyID     string
	PublicKey *rsa.PublicKey
}

// KeyRing holds a signing key and the keys tokens are verified with: the
// signing key and every verification key, by kid. A token's kid selects
// the key that verifies it, and a token with any other kid is refused.
type KeyRing struct {
	signing    *rsa.PrivateKey
	signingKID string
	verify     map[string]*rsa.PublicKey
	// order lists the kids in JWKS order, the signing key first.
	order []string
}

// NewKeyRing returns a key ring that signs with signing, published under
// signingKID, and verifies also with the verification keys. The caller
// has resolved and checked the keys: every kid is set, and no two keys
// share one.
func NewKeyRing(signing *rsa.PrivateKey, signingKID string, verification []VerificationKey) *KeyRing {
	r := &KeyRing{
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

// SigningKeyID returns the kid of the signing key, to set in the header
// of every JWT signed with the ring.
func (r *KeyRing) SigningKeyID() string { return r.signingKID }

// JWKS returns the published key set: the signing key first, then the
// verification keys.
func (r *KeyRing) JWKS() jose.JSONWebKeySet {
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
func (r *KeyRing) keyFunc(t *jwt.Token) (interface{}, error) {
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

// Signer returns the Fosite JWT signer of the ring: it signs with the
// signing key and verifies with the key the token's kid selects.
func (r *KeyRing) Signer() jwt.Signer {
	return &keyRingSigner{
		ring: r,
		sign: &jwt.DefaultSigner{GetPrivateKey: func(context.Context) (interface{}, error) { return r.signing, nil }},
	}
}

// keyRingSigner is a Fosite jwt.Signer over a KeyRing.
type keyRingSigner struct {
	ring *KeyRing
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
