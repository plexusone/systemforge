package pgstore

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/relyingparty/storetest"
)

func encodedKey(t *testing.T) string {
	t.Helper()
	return hex.EncodeToString(randomKey(t))
}

func TestKeysOptions(t *testing.T) {
	k1, k2 := encodedKey(t), encodedKey(t)
	tests := []struct {
		name     string
		keys     Keys
		wantOpts int
		wantErr  string
		wantIs   error
	}{
		{name: "missing key", keys: Keys{}, wantIs: ErrNoSessionKey},
		{name: "malformed key", keys: Keys{Key: "not-a-key"}, wantIs: ErrInvalidKey},
		{name: "short key", keys: Keys{Key: hex.EncodeToString([]byte("short"))}, wantIs: ErrInvalidKey},
		{name: "default id", keys: Keys{Key: k1}, wantOpts: 1},
		{name: "base64 key", keys: Keys{KeyID: "a", Key: base64.StdEncoding.EncodeToString(randomKey(t))}, wantOpts: 1},
		{name: "with previous", keys: Keys{KeyID: "k2", Key: k2, PreviousKeyID: "k1", PreviousKey: k1}, wantOpts: 2},
		{name: "previous without id", keys: Keys{Key: k2, PreviousKey: k1}, wantErr: "requires its key ID"},
		{name: "previous id without key", keys: Keys{Key: k2, PreviousKeyID: "k1"}, wantErr: "without a previous key"},
		{name: "previous id equals current", keys: Keys{Key: k2, PreviousKeyID: DefaultKeyID, PreviousKey: k1}, wantErr: "must differ"},
		{name: "malformed previous", keys: Keys{KeyID: "k2", Key: k2, PreviousKeyID: "k1", PreviousKey: "nope"}, wantIs: ErrInvalidKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := tt.keys.Options()
			switch {
			case tt.wantIs != nil:
				if !errors.Is(err, tt.wantIs) {
					t.Fatalf("err = %v, want %v", err, tt.wantIs)
				}
			case tt.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
			default:
				if err != nil {
					t.Fatalf("Options: %v", err)
				}
				if len(opts) != tt.wantOpts {
					t.Fatalf("len(opts) = %d, want %d", len(opts), tt.wantOpts)
				}
			}
		})
	}
}

func TestKeysFromEnv(t *testing.T) {
	t.Setenv("MYAPP_SESSION_KEY", "key")
	t.Setenv("MYAPP_SESSION_KEY_ID", "id")
	t.Setenv("MYAPP_SESSION_KEY_PREVIOUS", "prev")
	t.Setenv("MYAPP_SESSION_KEY_PREVIOUS_ID", "previd")
	t.Setenv("OTHER_SESSION_KEY", "other")
	got := KeysFromEnv("MYAPP_")
	want := Keys{KeyID: "id", Key: "key", PreviousKeyID: "previd", PreviousKey: "prev"}
	if got != want {
		t.Fatalf("KeysFromEnv = %+v, want %+v", got, want)
	}
	if empty := KeysFromEnv("UNSET_PREFIX_"); empty != (Keys{}) {
		t.Fatalf("KeysFromEnv(unset) = %+v, want zero", empty)
	}
}

func TestNewStoresRequiresKey(t *testing.T) {
	if _, err := NewStores(nil, Keys{}); !errors.Is(err, ErrNoSessionKey) {
		t.Fatalf("err = %v, want ErrNoSessionKey", err)
	}
}

func TestNewStoresRotation(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	k1, k2 := encodedKey(t), encodedKey(t)

	before, err := NewStores(db, Keys{KeyID: "k1", Key: k1})
	if err != nil {
		t.Fatalf("NewStores: %v", err)
	}
	tok := uuid.NewString()
	sess := storetest.NewSession(uuid.NewString(), "")
	if err := before.Sessions.Create(ctx, tok, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// After rotation the old key is decrypt-only: existing sessions survive.
	after, err := NewStores(db, Keys{KeyID: "k2", Key: k2, PreviousKeyID: "k1", PreviousKey: k1})
	if err != nil {
		t.Fatalf("NewStores rotated: %v", err)
	}
	got, err := after.Sessions.Get(ctx, tok)
	if err != nil {
		t.Fatalf("Get after rotation: %v", err)
	}
	storetest.AssertSessionEqual(t, got, sess)
	if after.LoginStates == nil {
		t.Fatal("LoginStates store not built")
	}
}
