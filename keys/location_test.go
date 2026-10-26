package keys_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/provider/local"
	"github.com/plexusone/omnivault/providers/memory"

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

// Without an audit store, lifecycle events are logged rather than dropped.
func TestLifecycleEventsAreLoggedWithoutAStore(t *testing.T) {
	var buf bytes.Buffer
	v := vaultWithRoot()
	k, err := keys.Open(context.Background(), keys.Options{
		Dir:      t.TempDir(),
		Root:     keys.VaultSource(v, "keyforge/root"),
		Purposes: []keyforge.Purpose{purpose},
		Logger:   slog.New(slog.NewTextHandler(&buf, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := k.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if !strings.Contains(buf.String(), "key lifecycle event") {
		t.Errorf("no lifecycle event logged; log: %q", buf.String())
	}
}

func vaultWithRoot() *memory.Provider {
	return memory.NewWithSecrets(map[string]string{"keyforge/root": rootKeyText(7)})
}
