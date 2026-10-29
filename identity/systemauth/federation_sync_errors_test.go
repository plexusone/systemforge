package systemauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type failingHumanLookup struct {
	*MemoryStorage
}

func (failingHumanLookup) GetHumanByEmail(context.Context, string) (*HumanPrincipal, error) {
	return nil, errors.New(`pq: relation "humans" does not exist`)
}

// TestIdentitySyncDoesNotLeakStorageErrors expects a storage failure to be
// reported generically while a known error keeps its fixed text.
func TestIdentitySyncDoesNotLeakStorageErrors(t *testing.T) {
	h := NewDefaultIdentitySyncHandler(failingHumanLookup{NewMemoryStorage()})
	resp, err := h.SyncIdentity(context.Background(), &IdentitySyncRequest{
		Action:   "create",
		Identity: &GlobalIdentity{ID: uuid.New(), Email: "a@example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != "failed" || strings.Contains(resp.Error, "humans") || resp.Error != "identity sync failed" {
		t.Errorf("storage failure response = %+v", resp)
	}

	resp, err = h.SyncIdentity(context.Background(), &IdentitySyncRequest{
		Action:   "create",
		Identity: &GlobalIdentity{ID: uuid.New()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Error != ErrEmailRequired.Error() {
		t.Errorf("missing email response = %+v, want %q", resp, ErrEmailRequired)
	}
}
