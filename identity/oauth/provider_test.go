package oauth

import (
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
)

// TestNewProviderConstructs guards against the provider's storage drifting
// from fosite.Storage, which makes Fosite's Compose panic.
func TestNewProviderConstructs(t *testing.T) {
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	p, err := NewProvider(db, DefaultConfig("https://auth.example.com", []byte("test-secret-32-bytes-long-xxxxxx")))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p == nil {
		t.Fatal("NewProvider returned nil")
	}
}
