package pglock

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plexusone/systemforge/internal/pgtest"
)

// These tests need PostgreSQL and skip unless SF_TEST_PG_DSN is set.

func TestLockerSerializesAcrossPools(t *testing.T) {
	// Lockers on separate pools of one database stand in for instances.
	dsn := pgtest.DSN(t)
	a, b := New(open(t, dsn), nil), New(open(t, dsn), nil)
	var inside, maxInside atomic.Int32
	var wg sync.WaitGroup
	for i := range 10 {
		l := a
		if i%2 == 1 {
			l = b
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := l.Lock(context.Background(), "org-1")
			if err != nil {
				t.Error(err)
				return
			}
			defer unlock()
			n := inside.Add(1)
			for {
				m := maxInside.Load()
				if n <= m || maxInside.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			inside.Add(-1)
		}()
	}
	wg.Wait()
	if maxInside.Load() != 1 {
		t.Fatalf("%d holders at once, want 1", maxInside.Load())
	}
}

func TestLockerWaitEndsWithContextAndUnlockReleases(t *testing.T) {
	l := New(pgtest.Open(t), nil)
	unlock, err := l.Lock(context.Background(), "k")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := l.Lock(ctx, "k"); err == nil {
		t.Fatal("took a held lock")
	}
	unlock()
	unlock() // a second call is harmless
	again, err := l.Lock(context.Background(), "k")
	if err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	again()
	// Other keys never wait.
	other, err := l.Lock(context.Background(), "other")
	if err != nil {
		t.Fatal(err)
	}
	other()
}

func TestLockOutlivesTheCallersContext(t *testing.T) {
	l := New(pgtest.Open(t), nil)
	ctx, cancel := context.WithCancel(context.Background())
	unlock, err := l.Lock(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	wait, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	if _, err := l.Lock(wait, "k"); err == nil {
		t.Fatal("the lock was released when its caller's context ended")
	}
	unlock()
}

// open opens a pool on dsn, closed when the test ends.
func open(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return db
}
