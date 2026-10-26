package bff

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// fakeEntClient is an in-memory EntClientInterface that keeps the sealed
// fields exactly as an Ent wrapper would store them.
type fakeEntClient struct {
	mu   sync.Mutex
	rows map[string]Session
}

func newFakeEntClient() *fakeEntClient { return &fakeEntClient{rows: map[string]Session{}} }

func (c *fakeEntClient) CreateBFFSession(_ context.Context, s *Session) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows[s.ID] = *s
	return nil
}

func (c *fakeEntClient) GetBFFSession(_ context.Context, id string) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.rows[id]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return &s, nil
}

func (c *fakeEntClient) UpdateBFFSession(_ context.Context, s *Session) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.rows[s.ID]; !ok {
		return ErrSessionNotFound
	}
	c.rows[s.ID] = *s
	return nil
}

func (c *fakeEntClient) DeleteBFFSession(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.rows, id)
	return nil
}

func (c *fakeEntClient) DeleteBFFSessionsByUserID(_ context.Context, userID uuid.UUID) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for id, s := range c.rows {
		if s.UserID == userID {
			delete(c.rows, id)
			n++
		}
	}
	return n, nil
}

func (c *fakeEntClient) TouchBFFSession(context.Context, string) error { return nil }

func (c *fakeEntClient) CleanupExpiredBFFSessions(context.Context, int) (int, error) { return 0, nil }

func (c *fakeEntClient) row(t *testing.T, id string) Session {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.rows[id]
	if !ok {
		t.Fatalf("no row for session %s", id)
	}
	return s
}

func (c *fakeEntClient) put(s Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows[s.ID] = s
}

func TestEntStore_SealerRotationRollback(t *testing.T) {
	client := newFakeEntClient()
	testSealerRotation(t, func(t *testing.T, sealer SessionSealer) Store {
		st, err := NewEntStore(EntStoreConfig{Client: client, Sealer: sealer})
		if err != nil {
			t.Fatal(err)
		}
		return st
	})
}

func TestNewEntStore_RequiresSealerOrKey(t *testing.T) {
	if _, err := NewEntStore(EntStoreConfig{Client: newFakeEntClient()}); !errors.Is(err, ErrSealerRequired) {
		t.Errorf("no sealer or key: err = %v, want ErrSealerRequired", err)
	}
	if _, err := NewEntStore(EntStoreConfig{Client: newFakeEntClient(), EncryptionKey: []byte("short")}); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("short key: err = %v, want ErrInvalidKeySize", err)
	}
}

// A sealed field opens only for the session and column it was sealed for,
// so a database writer cannot move one user's token into another's row.
func TestEntStore_BindsCiphertextToSessionAndField(t *testing.T) {
	ctx := context.Background()
	client := newFakeEntClient()
	st, err := NewEntStore(EntStoreConfig{Client: client, Sealer: testSealer(t)})
	if err != nil {
		t.Fatal(err)
	}
	victim, attacker := newTestSession(t), newTestSession(t)
	for _, s := range []*Session{victim, attacker} {
		if err := st.Create(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	victimRow := client.row(t, victim.ID)
	for _, secret := range []string{victim.AccessToken, victim.RefreshToken} {
		for _, stored := range [][]byte{victimRow.encryptedAccessToken, victimRow.encryptedRefreshToken} {
			if bytes.Contains(stored, []byte(secret)) {
				t.Fatal("token stored in plaintext")
			}
		}
	}

	moved := client.row(t, attacker.ID)
	moved.encryptedAccessToken = victimRow.encryptedAccessToken
	client.put(moved)
	if _, err := st.Get(ctx, attacker.ID); err == nil {
		t.Error("access token copied from another session opened")
	}

	swapped := client.row(t, victim.ID)
	swapped.encryptedAccessToken, swapped.encryptedRefreshToken = victimRow.encryptedRefreshToken, victimRow.encryptedAccessToken
	client.put(swapped)
	if _, err := st.Get(ctx, victim.ID); err == nil {
		t.Error("refresh token moved into the access token column opened")
	}
}

// Rows written by earlier versions (EncryptionKey, no key ID or session
// binding) still open while EncryptionKey is set, and are sealed in the
// current form on the next update.
func TestEntStore_OpensLegacyRows(t *testing.T) {
	ctx := context.Background()
	key := testKey(9)
	legacy, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}
	client := newFakeEntClient()
	s := newTestSession(t)
	row := *s
	row.AccessToken, row.RefreshToken = "", ""
	if row.encryptedAccessToken, err = legacy.EncryptString(s.AccessToken); err != nil {
		t.Fatal(err)
	}
	if row.encryptedRefreshToken, err = legacy.EncryptString(s.RefreshToken); err != nil {
		t.Fatal(err)
	}
	client.put(row)

	st, err := NewEntStore(EntStoreConfig{Client: client, EncryptionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Get(ctx, s.ID)
	if err != nil {
		t.Fatalf("legacy row: %v", err)
	}
	if got.AccessToken != s.AccessToken || got.RefreshToken != s.RefreshToken {
		t.Fatal("legacy row did not round-trip")
	}
	if err := st.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	resealed := client.row(t, s.ID).encryptedAccessToken
	if _, err := legacy.Decrypt(resealed); err == nil {
		t.Error("updated row is still in the legacy form")
	}

	// A keyring that holds the same key under EntStoreDefaultKeyID opens
	// rows the EncryptionKey-only store wrote, so the move to rotation needs
	// no re-encryption.
	rotating, err := NewKeyringSealer(EntStoreDefaultKeyID, map[string][]byte{EntStoreDefaultKeyID: key, "k2": testKey(2)})
	if err != nil {
		t.Fatal(err)
	}
	st2, err := NewEntStore(EntStoreConfig{Client: client, Sealer: rotating})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st2.Get(ctx, s.ID); err != nil {
		t.Errorf("keyring with the default key ID: %v", err)
	}

	// Without EncryptionKey, legacy rows no longer open.
	client.put(row)
	if _, err := st2.Get(ctx, s.ID); err == nil {
		t.Error("legacy row opened without EncryptionKey")
	}
}
