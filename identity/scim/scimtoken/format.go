package scimtoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"math/big"
	"strings"
)

// Token format.
//
// A token is Prefix, then BodyLength base62 characters encoding 256 random
// bits, then ChecksumLength base62 characters encoding the CRC-32 (IEEE) of
// the body:
//
//	sfscim_<43 base62 characters><6 base62 characters>
//
// A secret scanner can match it with the regular expression
// `sfscim_[0-9A-Za-z]{49}` and confirm a match offline with the checksum.
// The checksum also lets Authenticate refuse a mistyped or truncated token
// without a database lookup. It is not a secret and adds no strength.
const (
	// Prefix starts every token, so a leaked token is recognizable.
	Prefix = "sfscim_"
	// RandomBytes is the number of random bytes in a token (256 bits).
	RandomBytes = 32
	// BodyLength is the length of the base62 encoding of RandomBytes.
	BodyLength = 43
	// ChecksumLength is the length of the base62 encoding of the checksum.
	ChecksumLength = 6
	// Length is the length of a token.
	Length = len(Prefix) + BodyLength + ChecksumLength
	// DisplayLength is the length of the token prefix stored and shown to
	// identify a token: Prefix and the first 8 characters of the body.
	DisplayLength = len(Prefix) + 8
)

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// newToken returns a new random token.
func newToken() (string, error) {
	b := make([]byte, RandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("scimtoken: generating token: %w", err)
	}
	body := base62(b, BodyLength)
	return Prefix + body + checksum(body), nil
}

// wellFormed reports whether token has the token format and a matching
// checksum.
func wellFormed(token string) bool {
	if len(token) != Length || !strings.HasPrefix(token, Prefix) {
		return false
	}
	rest := token[len(Prefix):]
	for i := 0; i < len(rest); i++ {
		if strings.IndexByte(base62Alphabet, rest[i]) < 0 {
			return false
		}
	}
	body, sum := rest[:BodyLength], rest[BodyLength:]
	return checksum(body) == sum
}

// displayPrefix returns the non-secret part of token kept for display.
func displayPrefix(token string) string {
	return token[:DisplayLength]
}

// hashToken returns the hex SHA-256 of token. Tokens carry 256 random
// bits, so a fast hash is enough: there is nothing to brute-force.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func checksum(body string) string {
	sum := crc32.ChecksumIEEE([]byte(body))
	return base62(big.NewInt(int64(sum)).Bytes(), ChecksumLength)
}

// base62 encodes b as a big-endian number in base62, left-padded with
// zeros to width.
func base62(b []byte, width int) string {
	n := new(big.Int).SetBytes(b)
	base := big.NewInt(62)
	mod := new(big.Int)
	out := make([]byte, 0, width)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, base62Alphabet[mod.Int64()])
	}
	for len(out) < width {
		out = append(out, base62Alphabet[0])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}
