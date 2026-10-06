package pgstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// KeySize is the required encryption key length (AES-256).
const KeySize = 32

// sealVersion prefixes every ciphertext so the format can evolve.
const sealVersion byte = 1

var (
	// ErrNoEncryptionKey is returned by the constructors when neither
	// WithEncryptionKey nor WithInsecurePlaintext is given.
	ErrNoEncryptionKey = errors.New("pgstore: an encryption key is required (WithEncryptionKey), or WithInsecurePlaintext for development")
	// ErrInvalidKey is returned for keys that are not KeySize bytes or have
	// an empty or duplicate key ID.
	ErrInvalidKey = errors.New("pgstore: invalid encryption key")
	// ErrUnknownKeyID is returned when a row was sealed with a key that is
	// not configured (neither the encryption key nor a decryption key).
	ErrUnknownKeyID = errors.New("pgstore: row sealed with an unknown key ID")
	// ErrDecrypt is returned when a row fails authenticated decryption
	// (tampered, corrupted or moved between rows).
	ErrDecrypt = errors.New("pgstore: decrypting row failed")
)

// DecodeKey decodes a KeySize-byte key from hex or (standard or URL-safe,
// padded or not) base64, as typically held in an environment variable or
// secret manager. Generate one with `openssl rand -base64 32`.
func DecodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	decoders := []func(string) ([]byte, error){
		hex.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, decode := range decoders {
		if b, err := decode(s); err == nil && len(b) == KeySize {
			return b, nil
		}
	}
	return nil, fmt.Errorf("%w: want %d bytes encoded as hex or base64", ErrInvalidKey, KeySize)
}

// keyring seals with one primary key and opens with any configured key.
type keyring struct {
	primaryID string
	aeads     map[string]cipher.AEAD
	plaintext bool
}

func newKeyring(c *config) (*keyring, error) {
	kr := &keyring{aeads: map[string]cipher.AEAD{}, plaintext: c.insecurePlaintext}
	add := func(id string, key []byte) error {
		if id == "" {
			return fmt.Errorf("%w: empty key ID", ErrInvalidKey)
		}
		if len(key) != KeySize {
			return fmt.Errorf("%w: key %q is %d bytes, want %d", ErrInvalidKey, id, len(key), KeySize)
		}
		if _, dup := kr.aeads[id]; dup {
			return fmt.Errorf("%w: duplicate key ID %q", ErrInvalidKey, id)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		kr.aeads[id] = aead
		return nil
	}
	if c.encKey != nil {
		if err := add(c.encKey.id, c.encKey.key); err != nil {
			return nil, err
		}
		kr.primaryID = c.encKey.id
	}
	for _, k := range c.decKeys {
		if err := add(k.id, k.key); err != nil {
			return nil, err
		}
	}
	if kr.primaryID == "" && !kr.plaintext {
		return nil, ErrNoEncryptionKey
	}
	return kr, nil
}

// aad binds a ciphertext to its table, row and key ID, so a sealed value
// cannot be replayed into another row or relabeled with another key.
func aad(table, rowKey, keyID string) []byte {
	return []byte(table + "\x00" + rowKey + "\x00" + keyID)
}

// seal encrypts plaintext with the primary key. In insecure plaintext
// mode (no primary key) it returns the plaintext under an empty key ID.
func (kr *keyring) seal(table, rowKey string, plaintext []byte) (string, []byte, error) {
	if kr.primaryID == "" {
		return "", plaintext, nil
	}
	aead := kr.aeads[kr.primaryID]
	// The nonce gets its own buffer filled only by crypto/rand. Slicing it
	// out of the output buffer, whose first byte is the hardcoded version,
	// trips gosec G407 (hardcoded nonce) even though the nonce is random.
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, fmt.Errorf("pgstore: generating nonce: %w", err)
	}
	out := make([]byte, 0, 1+len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, sealVersion)
	out = append(out, nonce...)
	return kr.primaryID, aead.Seal(out, nonce, plaintext, aad(table, rowKey, kr.primaryID)), nil
}

// open decrypts a value sealed by seal.
func (kr *keyring) open(table, rowKey, keyID string, sealed []byte) ([]byte, error) {
	if keyID == "" {
		if !kr.plaintext {
			return nil, fmt.Errorf("%w: unencrypted row and WithInsecurePlaintext is not set", ErrUnknownKeyID)
		}
		return sealed, nil
	}
	aead, ok := kr.aeads[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKeyID, keyID)
	}
	ns := aead.NonceSize()
	if len(sealed) < 1+ns+aead.Overhead() || sealed[0] != sealVersion {
		return nil, ErrDecrypt
	}
	plaintext, err := aead.Open(nil, sealed[1:1+ns], sealed[1+ns:], aad(table, rowKey, keyID))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}
