package keys_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/plexusone/keyforge"
	kfaudit "github.com/plexusone/keyforge/audit"
	"github.com/plexusone/keyforge/provider/local"
	"github.com/plexusone/omnivault/providers/memory"

	sfaudit "github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/keys"
)

const purpose keyforge.Purpose = "test.secrets"

func rootKeyText(seed byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{seed}, local.RootKeySize))
}

func open(t *testing.T, dir string, store sfaudit.Store) *keys.Keys {
	t.Helper()
	v := memory.NewWithSecrets(map[string]string{"keyforge/root": rootKeyText(7)})
	k, err := keys.Open(context.Background(), keys.Options{
		Dir:      dir,
		Root:     keys.VaultSource(v, "keyforge/root"),
		Purposes: []keyforge.Purpose{purpose},
		Audit:    store,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() {
		if err := k.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return k
}

func TestSealOpenRoundTripAndBinding(t *testing.T) {
	ctx := context.Background()
	k := open(t, t.TempDir(), nil)

	sealed, err := k.Seal(ctx, purpose, []byte("token-value"), []byte("conn:1"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed, []byte("token-value")) {
		t.Fatal("sealed value contains the plaintext")
	}
	got, err := k.Open(ctx, purpose, sealed, []byte("conn:1"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != "token-value" {
		t.Fatalf("got %q", got)
	}
	if _, err := k.Open(ctx, purpose, sealed, []byte("conn:2")); err == nil {
		t.Fatal("open with another aad succeeded")
	}
	if err := k.Ready(ctx); err != nil {
		t.Fatalf("ready: %v", err)
	}
}

func TestReopenKeepsData(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	v := memory.NewWithSecrets(map[string]string{"root": rootKeyText(9)})
	o := keys.Options{Dir: dir, Root: keys.VaultSource(v, "root"), Purposes: []keyforge.Purpose{purpose}}

	k1, err := keys.Open(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k1.Seal(ctx, purpose, []byte("v"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := k1.Close(); err != nil {
		t.Fatal(err)
	}
	k2, err := keys.Open(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := k2.Close(); err != nil {
			t.Error(err)
		}
	}()
	if got, err := k2.Open(ctx, purpose, sealed, nil); err != nil || string(got) != "v" {
		t.Fatalf("after reopen: %q, %v", got, err)
	}
}

func TestVaultSource(t *testing.T) {
	ctx := context.Background()
	raw := bytes.Repeat([]byte{3}, local.RootKeySize)
	v := memory.NewWithSecrets(map[string]string{
		"b64":   base64.StdEncoding.EncodeToString(raw),
		"hex":   hex.EncodeToString(raw) + "\n",
		"short": "c2hvcnQ=",
	})
	for _, p := range []string{"b64", "hex"} {
		got, err := keys.VaultSource(v, p).RootKey(ctx)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("%s: %x, %v", p, got, err)
		}
	}
	// Reading twice works: decoding must not clear the vault's own copy.
	if _, err := keys.VaultSource(v, "b64").RootKey(ctx); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if _, err := keys.VaultSource(v, "short").RootKey(ctx); !errors.Is(err, local.ErrBadRootKey) {
		t.Fatalf("short key: %v", err)
	}
	if _, err := keys.VaultSource(v, "missing").RootKey(ctx); !errors.Is(err, local.ErrRootKeyUnavailable) {
		t.Fatalf("missing key: %v", err)
	}
}

func TestLifecycleEventsReachTheAuditTrail(t *testing.T) {
	store := sfaudit.NewMemoryStore(100)
	open(t, t.TempDir(), store)

	events, err := store.GetBySequence(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var created bool
	for _, e := range events {
		if e.EventType == "keys" && e.Action == string(kfaudit.KeyCreated) {
			created = true
			if e.Details["purpose"] != string(purpose) || e.Outcome != "success" {
				t.Fatalf("event: %+v", e)
			}
		}
	}
	if !created {
		t.Fatalf("no key.created event in %d events", len(events))
	}
}

func TestOptionsAreRequired(t *testing.T) {
	ctx := context.Background()
	v := memory.New()
	for name, o := range map[string]keys.Options{
		"dir":      {Root: keys.VaultSource(v, "r"), Purposes: []keyforge.Purpose{purpose}},
		"root":     {Dir: t.TempDir(), Purposes: []keyforge.Purpose{purpose}},
		"purposes": {Dir: t.TempDir(), Root: keys.VaultSource(v, "r")},
	} {
		if _, err := keys.Open(ctx, o); err == nil {
			t.Errorf("%s: missing option accepted", name)
		}
	}
}
