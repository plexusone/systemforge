package multiapp

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// scramIterations is the PBKDF2 iteration count PostgreSQL itself uses for
// SCRAM-SHA-256 verifiers (scram_iterations default).
const scramIterations = 4096

// scramSHA256Verifier computes the SCRAM-SHA-256 verifier PostgreSQL stores
// for password, so that ALTER ROLE ... PASSWORD carries the verifier and the
// plaintext never reaches the server, where statement logging
// (log_statement = 'ddl') would record it.
//
// PostgreSQL normalizes passwords with SASLprep before hashing; this
// function does not, so it accepts printable ASCII only, for which SASLprep
// is the identity.
func scramSHA256Verifier(password string) (string, error) {
	if password == "" {
		return "", errors.New("multiapp: empty password")
	}
	for _, c := range password {
		if c < 0x20 || c > 0x7e {
			return "", errors.New("multiapp: the password must be printable ASCII; set a non-ASCII password with ALTER ROLE yourself")
		}
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("multiapp: salt: %w", err)
	}
	return scramVerifierWithSalt(password, salt, scramIterations)
}

func scramVerifierWithSalt(password string, salt []byte, iterations int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("multiapp: pbkdf2: %w", err)
	}
	clientKey := hmacSHA256(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(salted, "Server Key")
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		iterations, b64(salt), b64(storedKey[:]), b64(serverKey)), nil
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg)) // hash.Hash.Write never returns an error
	return m.Sum(nil)
}
