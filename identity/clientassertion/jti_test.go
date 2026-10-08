package clientassertion

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent/enttest"

	_ "github.com/mattn/go-sqlite3"
)

func newStore(t *testing.T) *JTIStore {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return NewJTIStore(db)
}

func TestJTIReplay(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if err := s.Valid(ctx, "jti-1"); err != nil {
		t.Fatalf("unused JTI: %v", err)
	}
	if err := s.Mark(ctx, "jti-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	if err := s.Valid(ctx, "jti-1"); !errors.Is(err, fosite.ErrJTIKnown) {
		t.Errorf("replayed JTI error = %v, want ErrJTIKnown", err)
	}
	if err := s.Mark(ctx, "jti-1", time.Now().Add(time.Hour)); !errors.Is(err, fosite.ErrJTIKnown) {
		t.Errorf("marking a live JTI again error = %v, want ErrJTIKnown", err)
	}
	if err := s.Valid(ctx, "jti-2"); err != nil {
		t.Errorf("a different JTI: %v", err)
	}
}

func TestJTIExpiry(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	start := time.Now()
	s.now = func() time.Time { return start }

	if err := s.Mark(ctx, "jti-1", start.Add(time.Minute)); err != nil {
		t.Fatalf("Mark: %v", err)
	}

	// After expiry the JTI is no longer known and may be marked again;
	// marking prunes the expired row first.
	s.now = func() time.Time { return start.Add(2 * time.Minute) }
	if err := s.Valid(ctx, "jti-1"); err != nil {
		t.Errorf("expired JTI: %v", err)
	}
	if err := s.Mark(ctx, "jti-1", start.Add(time.Hour)); err != nil {
		t.Errorf("re-marking an expired JTI: %v", err)
	}
	n, err := s.db.ClientAssertionJTI.Query().Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("rows after prune and re-mark = %d, want 1", n)
	}
}
