package systemauthsvc_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/plexusone/omnivault/providers/memory"

	"github.com/plexusone/systemforge/identity/systemauthsvc"
	"github.com/plexusone/systemforge/secrets"
)

func TestLoadConfigWithResolver(t *testing.T) {
	r, err := secrets.New(memory.NewWithSecrets(map[string]string{"app/secret": "from-vault"}))
	if err != nil {
		t.Fatal(err)
	}
	data := "issuer: https://auth.example.com\nclients:\n  - id: app\n    secret: ${app/secret}\n"
	ctx := context.Background()

	cfg, err := systemauthsvc.LoadConfigBytesWithResolver(ctx, []byte(data), "yaml", r)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Clients[0].Secret != "from-vault" {
		t.Fatalf("bytes: client secret = %q, want from-vault", cfg.Clients[0].Secret)
	}

	path := filepath.Join(t.TempDir(), "systemauth.yaml")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = systemauthsvc.LoadConfigWithResolver(ctx, path, r)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Clients[0].Secret != "from-vault" {
		t.Fatalf("file: client secret = %q, want from-vault", cfg.Clients[0].Secret)
	}
}
