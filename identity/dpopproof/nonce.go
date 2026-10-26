package dpopproof

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// DefaultNonceLifetime is how long a server nonce is accepted when
// NewNonces is given none.
const DefaultNonceLifetime = 5 * time.Minute

// minNonceSecret is the shortest accepted nonce secret.
const minNonceSecret = 32

// ErrNonceSecret is returned by NewNonces for a short secret.
var ErrNonceSecret = fmt.Errorf("dpopproof: the nonce secret must be at least %d bytes", minNonceSecret)

// Nonces issues and checks server-provided DPoP nonces (RFC 9449 §8). A
// nonce is the time it was issued, authenticated with an HMAC under the
// secret, so it needs no storage: every instance given the same secret
// accepts the nonces any of them issued, for Lifetime after issue.
type Nonces struct {
	secret   []byte
	lifetime time.Duration
	now      func() time.Time
}

// NewNonces returns a nonce source keyed by secret (at least 32 bytes,
// the same on every instance). lifetime <= 0 uses DefaultNonceLifetime.
func NewNonces(secret []byte, lifetime time.Duration) (*Nonces, error) {
	if len(secret) < minNonceSecret {
		return nil, ErrNonceSecret
	}
	if lifetime <= 0 {
		lifetime = DefaultNonceLifetime
	}
	return &Nonces{secret: append([]byte(nil), secret...), lifetime: lifetime, now: time.Now}, nil
}

// Issue returns a new nonce.
func (n *Nonces) Issue() (string, error) {
	var buf [8 + sha256.Size]byte
	binary.BigEndian.PutUint64(buf[:8], uint64(n.now().Unix())) //nolint:gosec // G115: Unix time is positive
	copy(buf[8:], n.mac(buf[:8]))
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

func (n *Nonces) mac(ts []byte) []byte {
	h := hmac.New(sha256.New, n.secret)
	h.Write([]byte("dpop-nonce\x00"))
	h.Write(ts)
	return h.Sum(nil)
}

var errBadNonce = errors.New("not a current server nonce")

// validate is the dpop.Verifier nonce check.
func (n *Nonces) validate(_ context.Context, nonce string) error {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 8+sha256.Size {
		return errBadNonce
	}
	if !hmac.Equal(raw[8:], n.mac(raw[:8])) {
		return errBadNonce
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(raw[:8])), 0) //nolint:gosec // G115: checked by the MAC
	now := n.now()
	if issued.After(now.Add(time.Minute)) || now.Sub(issued) > n.lifetime {
		return errBadNonce
	}
	return nil
}
