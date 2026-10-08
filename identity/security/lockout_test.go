package security

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryLockoutStore_RecordAttempt(t *testing.T) {
	store := NewMemoryLockoutStore()
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	identifier := "user@example.com"

	// Record a failed attempt
	err := store.RecordAttempt(ctx, identifier, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cfg := DefaultLockoutConfig()
	status, err := store.GetStatus(ctx, identifier, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.FailedAttempts != 1 {
		t.Errorf("expected 1 failed attempt, got %d", status.FailedAttempts)
	}

	// Successful attempts should not be tracked
	err = store.RecordAttempt(ctx, identifier, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	status, _ = store.GetStatus(ctx, identifier, cfg)
	if status.FailedAttempts != 1 {
		t.Errorf("expected 1 failed attempt after success, got %d", status.FailedAttempts)
	}
}

func TestMemoryLockoutStore_Lock(t *testing.T) {
	store := NewMemoryLockoutStore()
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	identifier := "user@example.com"
	cfg := DefaultLockoutConfig()

	// Initially not locked
	status, _ := store.GetStatus(ctx, identifier, cfg)
	if status.IsLocked {
		t.Error("should not be locked initially")
	}

	// Lock the account
	lockUntil := time.Now().Add(5 * time.Minute)
	err := store.Lock(ctx, identifier, lockUntil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be locked now
	status, _ = store.GetStatus(ctx, identifier, cfg)
	if !status.IsLocked {
		t.Error("should be locked")
	}
	if status.LockedUntil.IsZero() {
		t.Error("LockedUntil should be set")
	}

	// Unlock
	err = store.Unlock(ctx, identifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	status, _ = store.GetStatus(ctx, identifier, cfg)
	if status.IsLocked {
		t.Error("should be unlocked")
	}
}

func TestLockout_RecordFailure(t *testing.T) {
	store := NewMemoryLockoutStore()
	defer func() { _ = store.Close() }()

	lockout := NewLockout(store, WithMaxAttempts(3))
	ctx := context.Background()
	identifier := "user@example.com"

	// First 2 failures should not lock
	for i := 0; i < 2; i++ {
		err := lockout.RecordFailure(ctx, identifier)
		if err != nil {
			t.Errorf("attempt %d: unexpected error: %v", i+1, err)
		}
	}

	// 3rd failure should lock
	err := lockout.RecordFailure(ctx, identifier)
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("expected ErrAccountLocked, got %v", err)
	}

	// Should be locked
	locked, err := lockout.IsLocked(ctx, identifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !locked {
		t.Error("account should be locked")
	}
}

func TestLockout_RecordSuccess(t *testing.T) {
	store := NewMemoryLockoutStore()
	defer func() { _ = store.Close() }()

	lockout := NewLockout(store, WithMaxAttempts(3))
	ctx := context.Background()
	identifier := "user@example.com"

	// Record 2 failures
	_ = lockout.RecordFailure(ctx, identifier)
	_ = lockout.RecordFailure(ctx, identifier)

	status, _ := lockout.GetStatus(ctx, identifier)
	if status.FailedAttempts != 2 {
		t.Errorf("expected 2 failed attempts, got %d", status.FailedAttempts)
	}

	// Record success - should reset
	err := lockout.RecordSuccess(ctx, identifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	status, _ = lockout.GetStatus(ctx, identifier)
	if status.FailedAttempts != 0 {
		t.Errorf("expected 0 failed attempts after success, got %d", status.FailedAttempts)
	}
}

func TestLockout_CheckAndRecord(t *testing.T) {
	store := NewMemoryLockoutStore()
	defer func() { _ = store.Close() }()

	lockout := NewLockout(store, WithMaxAttempts(2))
	ctx := context.Background()
	identifier := "user@example.com"

	// First failure
	err := lockout.CheckAndRecord(ctx, identifier, false)
	if err != nil {
		t.Errorf("first failure: unexpected error: %v", err)
	}

	// Second failure - should lock
	err = lockout.CheckAndRecord(ctx, identifier, false)
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("second failure: expected ErrAccountLocked, got %v", err)
	}

	// Subsequent attempts should fail with ErrAccountLocked
	err = lockout.CheckAndRecord(ctx, identifier, false)
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("third attempt: expected ErrAccountLocked, got %v", err)
	}

	// Even successful attempts should fail when locked
	err = lockout.CheckAndRecord(ctx, identifier, true)
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("success while locked: expected ErrAccountLocked, got %v", err)
	}
}

func TestLockout_Unlock(t *testing.T) {
	store := NewMemoryLockoutStore()
	defer func() { _ = store.Close() }()

	lockout := NewLockout(store, WithMaxAttempts(1))
	ctx := context.Background()
	identifier := "user@example.com"

	// Lock the account
	_ = lockout.RecordFailure(ctx, identifier)

	locked, _ := lockout.IsLocked(ctx, identifier)
	if !locked {
		t.Fatal("should be locked")
	}

	// Unlock
	err := lockout.Unlock(ctx, identifier)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	locked, _ = lockout.IsLocked(ctx, identifier)
	if locked {
		t.Error("should be unlocked")
	}
}

func TestLockout_RemainingAttempts(t *testing.T) {
	store := NewMemoryLockoutStore()
	defer func() { _ = store.Close() }()

	lockout := NewLockout(store, WithMaxAttempts(5))
	ctx := context.Background()
	identifier := "user@example.com"

	status, _ := lockout.GetStatus(ctx, identifier)
	if status.RemainingAttempts != 5 {
		t.Errorf("expected 5 remaining, got %d", status.RemainingAttempts)
	}

	_ = lockout.RecordFailure(ctx, identifier)
	_ = lockout.RecordFailure(ctx, identifier)

	status, _ = lockout.GetStatus(ctx, identifier)
	if status.RemainingAttempts != 3 {
		t.Errorf("expected 3 remaining, got %d", status.RemainingAttempts)
	}
}

func TestLockout_LockoutDuration(t *testing.T) {
	store := NewMemoryLockoutStore()
	defer func() { _ = store.Close() }()

	lockout := NewLockout(store,
		WithMaxAttempts(1),
		WithLockoutDuration(100*time.Millisecond),
	)
	ctx := context.Background()
	identifier := "user@example.com"

	// Trigger lockout
	_ = lockout.RecordFailure(ctx, identifier)

	locked, _ := lockout.IsLocked(ctx, identifier)
	if !locked {
		t.Fatal("should be locked")
	}

	// Wait for lockout to expire
	time.Sleep(150 * time.Millisecond)

	locked, _ = lockout.IsLocked(ctx, identifier)
	if locked {
		t.Error("lockout should have expired")
	}
}

func TestMemoryLockoutStore_Close(t *testing.T) {
	store := NewMemoryLockoutStore()

	err := store.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Operations after close should fail
	err = store.RecordAttempt(context.Background(), "test", false)
	if !errors.Is(err, ErrStorageFailure) {
		t.Errorf("expected ErrStorageFailure, got %v", err)
	}

	// Double close should be safe
	err = store.Close()
	if err != nil {
		t.Errorf("double close should not error: %v", err)
	}
}

// TestLockoutTreatsEverySpellingAsOneAccount verifies that varying case or
// whitespace does not restart the count of failed attempts.
func TestLockoutTreatsEverySpellingAsOneAccount(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryLockoutStore()
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	l := NewLockout(store, WithMaxAttempts(3), WithLockoutDuration(time.Minute))

	var last error
	for _, spelling := range []string{"Bob@Example.com", "bob@example.com", " bob@example.com "} {
		last = l.RecordFailure(ctx, spelling)
	}
	if !errors.Is(last, ErrAccountLocked) {
		t.Fatalf("three failures under three spellings = %v, want the account locked", last)
	}
	for _, spelling := range []string{"bob@example.com", "BOB@EXAMPLE.COM", "\tbob@example.com\n"} {
		if locked, err := l.IsLocked(ctx, spelling); err != nil || !locked {
			t.Errorf("IsLocked(%q) = %v, %v", spelling, locked, err)
		}
	}
	if err := l.Unlock(ctx, "BOB@example.com"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if locked, err := l.IsLocked(ctx, "bob@example.com"); err != nil || locked {
		t.Errorf("after Unlock under another spelling: %v, %v", locked, err)
	}
}
