package systemauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ory/fosite"
)

// TestMemoryStorageRejectsReplayedAssertions verifies that the default
// storage, like the database one, refuses a client assertion it has seen.
func TestMemoryStorageRejectsReplayedAssertions(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()
	if err := s.ClientAssertionJWTValid(ctx, "jti-1"); err != nil {
		t.Fatalf("fresh JTI: %v", err)
	}
	if err := s.SetClientAssertionJWT(ctx, "jti-1", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetClientAssertionJWT: %v", err)
	}
	if err := s.ClientAssertionJWTValid(ctx, "jti-1"); !errors.Is(err, fosite.ErrJTIKnown) {
		t.Errorf("replayed assertion = %v, want ErrJTIKnown", err)
	}
}
