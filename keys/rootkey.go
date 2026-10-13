package keys

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/plexusone/keyforge/provider/local"
	"github.com/plexusone/omnivault/vault"
)

// VaultSource returns a root key source that reads the key from a secret in
// an omnivault vault. The secret holds 32 bytes as standard base64 or as 64
// hex digits, the forms keyforge accepts from a file or the environment.
func VaultSource(v vault.Vault, path string) local.RootKeySource {
	return vaultSource{v: v, path: path}
}

type vaultSource struct {
	v    vault.Vault
	path string
}

func (s vaultSource) RootKey(ctx context.Context) ([]byte, error) {
	if s.v == nil {
		return nil, fmt.Errorf("%w: no vault", local.ErrRootKeyUnavailable)
	}
	sec, err := s.v.Get(ctx, s.path)
	if err != nil {
		if errors.Is(err, vault.ErrSecretNotFound) {
			return nil, fmt.Errorf("%w: secret %s not found in %s", local.ErrRootKeyUnavailable, s.path, s.v.Name())
		}
		// The vault's error is wrapped so its cause is visible; omnivault
		// errors name paths, never values.
		return nil, fmt.Errorf("%w: %w", local.ErrRootKeyUnavailable, err)
	}
	// Copy first: a vault may return its own buffer, which decoding clears.
	return decodeRootKey(append([]byte(nil), sec.Bytes()...))
}

// decodeRootKey parses 32 bytes from base64 or hex text, clearing the text.
// It matches keyforge's own parsing for file and environment sources.
func decodeRootKey(text []byte) ([]byte, error) {
	defer clear(text)
	s := strings.TrimSpace(string(text))
	if len(s) == 2*local.RootKeySize {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == local.RootKeySize {
		return b, nil
	}
	return nil, local.ErrBadRootKey
}
