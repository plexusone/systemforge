package systemauth

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/plexusone/omnivault/providers/memory"
	"github.com/plexusone/omnivault/vault"

	"github.com/plexusone/systemforge/secrets"
)

//nolint:gosec // G101: secret references for the test, not credentials
const secretsTestYAML = `
database:
  driver: sqlite
  dsn: ${SFT_DSN}
keys:
  private_key_pem: ${SFT_PEM}
tokens:
  hmac_secret: ${SFT_HMAC}
clients:
  - id: app
    secret: pre-$SFT_CLIENT-post
rate_limit:
  redis_url: ${SFT_REDIS}
dpop:
  nonce_secret: ${SFT_MISSING}
`

func TestDecodeConfigResolvesFromEnvironment(t *testing.T) {
	pem := "-----BEGIN KEY-----\nab$cd${X}\n-----END KEY-----"
	t.Setenv("SFT_DSN", "file:test.db")
	t.Setenv("SFT_PEM", pem)
	t.Setenv("SFT_HMAC", "h$mac")
	t.Setenv("SFT_CLIENT", "cs")
	t.Setenv("SFT_REDIS", "redis://:pw@redis:6379/0")

	cfg, err := DecodeConfig([]byte(secretsTestYAML), FormatYAML)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.DSN != "file:test.db" {
		t.Errorf("dsn = %q", cfg.Database.DSN)
	}
	if cfg.Keys.PrivateKeyPEM != pem {
		t.Errorf("private_key_pem = %q, want %q (the whole reference is not re-scanned)", cfg.Keys.PrivateKeyPEM, pem)
	}
	if cfg.Tokens.HMACSecret != "h$mac" {
		t.Errorf("hmac_secret = %q", cfg.Tokens.HMACSecret)
	}
	if cfg.Clients[0].Secret != "pre-cs-post" {
		t.Errorf("client secret = %q", cfg.Clients[0].Secret)
	}
	if cfg.RateLimit.RedisURL != "redis://:pw@redis:6379/0" {
		t.Errorf("rate_limit.redis_url = %q", cfg.RateLimit.RedisURL)
	}
	if cfg.DPoP.NonceSecret != "" {
		t.Errorf("nonce_secret = %q, want empty for a missing variable", cfg.DPoP.NonceSecret)
	}
}

func TestDecodeConfigWithResolverReadsVault(t *testing.T) {
	t.Setenv("SFT_DSN", "from-env")
	r, err := secrets.New(memory.NewWithSecrets(map[string]string{
		"SFT_DSN":  "from-vault",
		"SFT_PEM":  "pem$data",
		"SFT_HMAC": "vault-hmac",
	}))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := DecodeConfigWithResolver(context.Background(), []byte(secretsTestYAML), FormatYAML, r)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.DSN != "from-vault" || cfg.Keys.PrivateKeyPEM != "pem$data" || cfg.Tokens.HMACSecret != "vault-hmac" {
		t.Fatalf("got dsn %q pem %q hmac %q", cfg.Database.DSN, cfg.Keys.PrivateKeyPEM, cfg.Tokens.HMACSecret)
	}
	if cfg.Clients[0].Secret != "pre--post" {
		t.Fatalf("client secret = %q, want the missing secret expanded to empty", cfg.Clients[0].Secret)
	}
}

func TestDecodeConfigSecretsVaultURI(t *testing.T) {
	t.Setenv("SFTV_SFT_DSN", "prefixed-dsn")
	t.Setenv("SFT_SECRETS_VAULT", "env://SFTV_")
	data := "secrets:\n  vault: ${SFT_SECRETS_VAULT}\ndatabase:\n  driver: sqlite\n  dsn: ${SFT_DSN}\n"
	cfg, err := DecodeConfig([]byte(data), FormatYAML)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database.DSN != "prefixed-dsn" {
		t.Fatalf("dsn = %q, want prefixed-dsn", cfg.Database.DSN)
	}

	if _, err := DecodeConfig([]byte("secrets:\n  vault: nosuchscheme://x\n"), FormatYAML); err == nil {
		t.Fatal("unknown secrets.vault scheme accepted")
	}
}

type failingVault struct{ vault.Vault }

var errVaultDown = errors.New("vault down")

func (failingVault) Get(context.Context, string) (*vault.Secret, error) { return nil, errVaultDown }
func (failingVault) Name() string                                       { return "failing" }
func (failingVault) Close() error                                       { return nil }

func TestLoadConfigWithResolverReturnsBackendErrors(t *testing.T) {
	r, err := secrets.New(failingVault{})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "c.yaml")
	//nolint:gosec // G101: a secret reference, not a credential
	if err := SaveConfig(&Config{Issuer: "https://auth.example.com", Tokens: TokenConfig{HMACSecret: "${SFT_HMAC}"}}, path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigWithResolver(context.Background(), path, r); !errors.Is(err, errVaultDown) {
		t.Fatalf("LoadConfigWithResolver error = %v, want %v", err, errVaultDown)
	}
}
