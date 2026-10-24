package keys_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/provider/local"

	"github.com/plexusone/systemforge/keys"
)

// A root key stored where a backup of the keys directory would include it
// is refused before the key system opens.
func TestCheckRootKeyLocation(t *testing.T) {
	keysDir := filepath.Join(t.TempDir(), "keys")
	tests := []struct {
		name, vault, secret string
		inside              bool
	}{
		{"same directory", "file://" + keysDir, "root", true},
		{"subdirectory", "file://" + keysDir, "sub/root", true},
		{"secret path climbing in", "file://" + filepath.Dir(keysDir), "keys/root", true},
		{"sibling directory", "file://" + filepath.Join(filepath.Dir(keysDir), "secrets"), "root", false},
		{"not a file vault", "env://", "ROOT_KEY", false},
	}
	for _, tt := range tests {
		err := keys.CheckRootKeyLocation(tt.vault, tt.secret, keysDir)
		if got := errors.Is(err, keys.ErrRootKeyInKeysDir); got != tt.inside {
			t.Errorf("%s: err = %v, want inside=%v", tt.name, err, tt.inside)
		}
	}
}

// A root key source that names its file is checked by Open itself.
func TestOpenRefusesRootKeyFileInDir(t *testing.T) {
	dir := t.TempDir()
	_, err := keys.Open(context.Background(), keys.Options{
		Dir:      dir,
		Root:     local.FileSource(filepath.Join(dir, "nested", "root.key")),
		Purposes: []keyforge.Purpose{purpose},
	})
	if !errors.Is(err, keys.ErrRootKeyInKeysDir) {
		t.Fatalf("err = %v, want ErrRootKeyInKeysDir", err)
	}
}
