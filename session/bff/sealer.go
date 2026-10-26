package bff

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/plexusone/keyforge"
)

// SessionSealer encrypts session secrets (tokens and DPoP keys) before a
// store persists them, and decrypts them on load. aad is bound into the
// ciphertext, so a sealed value only opens for the session it was sealed
// for. Implementations must be safe for concurrent use.
//
// Use NewKeyringSealer for application-held keys, or NewKeysSealer to seal
// with a keyforge purpose key (see the keys package).
type SessionSealer interface {
	Seal(ctx context.Context, plaintext, aad []byte) ([]byte, error)
	Open(ctx context.Context, sealed, aad []byte) ([]byte, error)
}

var (
	// ErrUnknownSealingKey is returned when sealed data names a key ID the
	// sealer does not hold.
	ErrUnknownSealingKey = errors.New("bff: sealed session data uses an unknown key")
	// ErrMalformedSealedData is returned for sealed data that cannot be
	// parsed.
	ErrMalformedSealedData = errors.New("bff: malformed sealed session data")
	// ErrPlaintextTooLarge is returned for session data larger than
	// MaxSealPlaintext.
	ErrPlaintextTooLarge = errors.New("bff: session data too large to seal")
)

// MaxSealPlaintext is the most session data a KeyringSealer seals, far
// above any session; it keeps the sealed buffer's size computation in range.
const MaxSealPlaintext = 64 << 20

// keyringSealerVersion prefixes data sealed by KeyringSealer.
const keyringSealerVersion byte = 1

// KeyringSealer seals with AES-256-GCM under named 32-byte keys. It seals
// with the active key and opens with whichever key the sealed data names,
// so keys can be rotated while the active key N and the previous key N-1
// both open sessions:
//
//  1. Pre-stage: add N to the ring while N-1 stays active, and deploy
//     everywhere.
//  2. Promote: make N active, keep N-1 in the ring, and drop N-2. Rolling
//     this deploy back returns to step 1, which still opens sessions
//     sealed with N.
//
// Never add a key and drop the previous one in the same deploy.
//
// Sealed form: version (1 byte) | key ID length (1 byte) | key ID | nonce |
// ciphertext and tag.
type KeyringSealer struct {
	active string
	aeads  map[string]cipher.AEAD
}

// NewKeyringSealer returns a sealer over keys (key ID to 32-byte AES-256
// key) that seals with activeKeyID. Key IDs must be 1 to 255 bytes.
func NewKeyringSealer(activeKeyID string, keys map[string][]byte) (*KeyringSealer, error) {
	if _, ok := keys[activeKeyID]; !ok {
		return nil, fmt.Errorf("bff: active sealing key %q is not in the keyring", activeKeyID)
	}
	s := &KeyringSealer{active: activeKeyID, aeads: make(map[string]cipher.AEAD, len(keys))}
	for id, key := range keys {
		if id == "" || len(id) > 255 {
			return nil, fmt.Errorf("bff: sealing key ID %q must be 1 to 255 bytes", id)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("bff: sealing key %q: %w", id, ErrInvalidKeySize)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		s.aeads[id] = gcm
	}
	return s, nil
}

// Seal encrypts plaintext under the active key, bound to aad.
func (s *KeyringSealer) Seal(_ context.Context, plaintext, aad []byte) ([]byte, error) {
	if len(plaintext) > MaxSealPlaintext {
		return nil, ErrPlaintextTooLarge
	}
	gcm := s.aeads[s.active]
	out := make([]byte, 0, 2+len(s.active)+gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	out = append(out, keyringSealerVersion, byte(len(s.active))) //nolint:gosec // G115: NewKeyringSealer limits key IDs to 255 bytes
	out = append(out, s.active...)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

// Open decrypts data sealed by Seal with the same aad.
func (s *KeyringSealer) Open(_ context.Context, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < 2 || sealed[0] != keyringSealerVersion {
		return nil, ErrMalformedSealedData
	}
	idLen := int(sealed[1])
	if len(sealed) < 2+idLen {
		return nil, ErrMalformedSealedData
	}
	gcm, ok := s.aeads[string(sealed[2:2+idLen])]
	if !ok {
		return nil, ErrUnknownSealingKey
	}
	rest := sealed[2+idLen:]
	if len(rest) < gcm.NonceSize() {
		return nil, ErrMalformedSealedData
	}
	return gcm.Open(nil, rest[:gcm.NonceSize()], rest[gcm.NonceSize():], aad)
}

// PurposeKeys seals and opens data under a keyforge purpose. *keys.Keys
// implements it.
type PurposeKeys interface {
	Seal(ctx context.Context, purpose keyforge.Purpose, plaintext, aad []byte) ([]byte, error)
	Open(ctx context.Context, purpose keyforge.Purpose, sealed, aad []byte) ([]byte, error)
}

// NewKeysSealer returns a SessionSealer that seals under purpose with k,
// typically a *keys.Keys. keyforge records the key version in each
// envelope and handles rotation.
func NewKeysSealer(k PurposeKeys, purpose keyforge.Purpose) SessionSealer {
	return keysSealer{keys: k, purpose: purpose}
}

type keysSealer struct {
	keys    PurposeKeys
	purpose keyforge.Purpose
}

func (s keysSealer) Seal(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	return s.keys.Seal(ctx, s.purpose, plaintext, aad)
}

func (s keysSealer) Open(ctx context.Context, sealed, aad []byte) ([]byte, error) {
	return s.keys.Open(ctx, s.purpose, sealed, aad)
}
