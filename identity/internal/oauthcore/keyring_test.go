package oauthcore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	gojwt "github.com/golang-jwt/jwt/v5"
)

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestKeyRingRefusesUnknownKID verifies that a token signed by a key the
// ring does not hold, or naming an unknown kid, is refused.
func TestKeyRingRefusesUnknownKID(t *testing.T) {
	k1, other := rsaKey(t), rsaKey(t)
	ring := NewKeyRing(k1, "k1", nil)
	signer := ring.Signer()
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

// TestKeyRingJWKSOrder verifies that the JWKS lists the signing key first,
// then the verification keys in order.
func TestKeyRingJWKSOrder(t *testing.T) {
	k1, k2, k3 := rsaKey(t), rsaKey(t), rsaKey(t)
	ring := NewKeyRing(k1, "k1", []VerificationKey{{KeyID: "k2", PublicKey: &k2.PublicKey}, {KeyID: "k3", PublicKey: &k3.PublicKey}})
	if ring.SigningKeyID() != "k1" {
		t.Errorf("SigningKeyID = %q", ring.SigningKeyID())
	}
	var kids []string
	for _, k := range ring.JWKS().Keys {
		kids = append(kids, k.KeyID)
	}
	if strings.Join(kids, ",") != "k1,k2,k3" {
		t.Errorf("JWKS kids = %v", kids)
	}
}
