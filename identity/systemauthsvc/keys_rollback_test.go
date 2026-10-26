package systemauthsvc_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/omnivault"

	"github.com/plexusone/systemforge/connections"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
	"github.com/plexusone/systemforge/keys"
)

// openKeysPlain opens the configured connections keyring without accepting
// a rollback, as the server does at startup.
func openKeysPlain(t *testing.T, cfg *systemauthsvc.Config) error {
	t.Helper()
	cc := cfg.Connections
	v, err := omnivault.VaultFromURI(cc.Vault)
	if err != nil {
		t.Fatal(err)
	}
	k, err := keys.Open(context.Background(), keys.Options{
		Dir:      cc.KeysDir,
		Root:     keys.VaultSource(v, cc.RootKey),
		Purposes: []keyforge.Purpose{connections.Purpose},
	})
	if err != nil {
		return err
	}
	return k.Close()
}

// backupStateFiles returns the keyring rollback state files under dir.
func backupStateFiles(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".backup") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

func TestAcceptKeyRollbackAcceptsAMovedKeyring(t *testing.T) {
	cfg := connectionsConfig(t)
	ctx := context.Background()

	// Create the keyring.
	if err := openKeysPlain(t, cfg); err != nil {
		t.Fatalf("create keyring: %v", err)
	}
	states := backupStateFiles(t, cfg.Connections.KeysDir)
	if len(states) == 0 {
		t.Fatal("no rollback state file was written")
	}
	// Move the keyring to a new host without its rollback state.
	for _, p := range states {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := openKeysPlain(t, cfg); err == nil {
		t.Fatal("a keyring with unverifiable rollback state opened without accepting it")
	}

	if err := systemauthsvc.AcceptKeyRollback(ctx, cfg, discardLogger()); err != nil {
		t.Fatalf("accept rollback: %v", err)
	}
	// Later starts succeed without the option.
	if err := openKeysPlain(t, cfg); err != nil {
		t.Fatalf("open after accepting: %v", err)
	}
}

func TestAcceptKeyRollbackNeedsConnections(t *testing.T) {
	if err := systemauthsvc.AcceptKeyRollback(context.Background(), &systemauthsvc.Config{}, discardLogger()); err == nil {
		t.Fatal("accepted a rollback with no connections keyring configured")
	}
}
