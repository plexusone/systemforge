package secrets_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/plexusone/omnivault"
	"github.com/plexusone/omnivault/providers/memory"
	"github.com/plexusone/omnivault/vault"

	"github.com/plexusone/systemforge/secrets"
)

func TestEnvExpandMatchesOSExpandEnv(t *testing.T) {
	t.Setenv("SF_SECRETS_A", "alpha")
	t.Setenv("SF_SECRETS_EMPTY", "")
	t.Setenv("SF_SECRETS_DOLLAR", "x$SF_SECRETS_A")
	r := secrets.Env()
	ctx := context.Background()
	for _, in := range []string{
		"",
		"plain",
		"${SF_SECRETS_A}",
		"$SF_SECRETS_A",
		"pre-${SF_SECRETS_A}-post",
		"$SF_SECRETS_A$SF_SECRETS_A",
		"${SF_SECRETS_MISSING}",
		"$SF_SECRETS_MISSING/x",
		"${SF_SECRETS_EMPTY}",
		"${SF_SECRETS_DOLLAR}",
		"postgres://u:${SF_SECRETS_A}@h/db?sslmode=disable",
		"cost $5",
		"trailing $",
		"${bad",
		"${}",
		"$$",
		"$1 $* $@",
	} {
		got, err := r.Expand(ctx, in)
		if err != nil {
			t.Fatalf("Expand(%q): %v", in, err)
		}
		if want := os.ExpandEnv(in); got != want {
			t.Errorf("Expand(%q) = %q, os.ExpandEnv = %q", in, got, want)
		}
	}
}

func TestExpandWholeKeepsDollarInSecret(t *testing.T) {
	pem := "-----BEGIN KEY-----\nab$cd${EF}\n-----END KEY-----\n"
	t.Setenv("SF_SECRETS_PEM", pem)
	r := secrets.Env()
	ctx := context.Background()

	got, err := r.ExpandWhole(ctx, "  ${SF_SECRETS_PEM}\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != pem {
		t.Fatalf("ExpandWhole = %q, want %q", got, pem)
	}

	// Not a whole reference: expanded like os.ExpandEnv.
	t.Setenv("SF_SECRETS_A", "alpha")
	got, err = r.ExpandWhole(ctx, "k-${SF_SECRETS_A}")
	if err != nil {
		t.Fatal(err)
	}
	if got != "k-alpha" {
		t.Fatalf("ExpandWhole = %q, want k-alpha", got)
	}
}

func TestMemoryVault(t *testing.T) {
	r, err := secrets.New(memory.NewWithSecrets(map[string]string{
		"db/password":  "s3cret",
		"CLIENT_TOKEN": "tok",
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx := context.Background()
	got, err := r.Expand(ctx, "postgres://app:${db/password}@db/app $CLIENT_TOKEN ${MISSING}")
	if err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G101: a test fixture
	if want := "postgres://app:s3cret@db/app tok "; got != want {
		t.Fatalf("Expand = %q, want %q", got, want)
	}
	if _, ok, err := r.Lookup(ctx, "MISSING"); err != nil || ok {
		t.Fatalf("Lookup(MISSING) = ok %v, err %v; want not found, no error", ok, err)
	}
}

func TestFromURI(t *testing.T) {
	t.Setenv("SFTEST_TOKEN", "prefixed")
	r, err := secrets.FromURI("env://SFTEST_")
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Expand(context.Background(), "${TOKEN}")
	if err != nil {
		t.Fatal(err)
	}
	if got != "prefixed" {
		t.Fatalf("Expand = %q, want prefixed", got)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := secrets.FromURI("nosuchscheme://x"); err == nil {
		t.Fatal("FromURI with an unknown scheme succeeded")
	}
}

// failingVault fails every read with a backend error.
type failingVault struct{ vault.Vault }

var errBackend = errors.New("backend unavailable")

func (failingVault) Get(context.Context, string) (*vault.Secret, error) {
	return nil, errBackend
}
func (failingVault) Name() string { return "failing" }
func (failingVault) Close() error { return nil }

func TestBackendErrorIsReturned(t *testing.T) {
	r, err := secrets.New(failingVault{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := r.Expand(ctx, "x${A}y"); !errors.Is(err, errBackend) {
		t.Fatalf("Expand error = %v, want %v", err, errBackend)
	}
	if _, err := r.ExpandWhole(ctx, "${A}"); !errors.Is(err, errBackend) {
		t.Fatalf("ExpandWhole error = %v, want %v", err, errBackend)
	}
	// No reference: the vault is not consulted.
	if got, err := r.Expand(ctx, "plain"); err != nil || got != "plain" {
		t.Fatalf("Expand(plain) = %q, %v", got, err)
	}
}

func TestNewNilVault(t *testing.T) {
	var v omnivault.Vault
	if _, err := secrets.New(v); err == nil {
		t.Fatal("New(nil) succeeded")
	}
}
