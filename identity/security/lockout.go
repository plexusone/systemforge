// Package security provides security features for identity management including
// account lockout protection against brute-force attacks.
package security

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// Common errors returned by the lockout service.
var (
	ErrAccountLocked    = errors.New("account is locked")
	ErrStorageFailure   = errors.New("lockout storage failure")
	ErrInvalidThreshold = errors.New("invalid lockout threshold")
)

// LockoutConfig configures the account lockout behavior.
type LockoutConfig struct {
	// MaxAttempts is the number of failed attempts before lockout.
	// Default: 5
	MaxAttempts int

	// LockoutDuration is how long the account stays locked.
	// Default: 15 minutes
	LockoutDuration time.Duration

	// AttemptWindow is the time window for counting attempts.
	// Attempts older than this are not counted.
	// Default: 15 minutes
	AttemptWindow time.Duration

	// CleanupInterval is how often to clean up old attempts.
	// Default: 5 minutes
	CleanupInterval time.Duration
}

// DefaultLockoutConfig returns sensible defaults for account lockout.
func DefaultLockoutConfig() LockoutConfig {
	return LockoutConfig{
		MaxAttempts:     5,
		LockoutDuration: 15 * time.Minute,
		AttemptWindow:   15 * time.Minute,
		CleanupInterval: 5 * time.Minute,
	}
}

// LockoutStatus contains the current lockout state for an identifier.
type LockoutStatus struct {
	// IsLocked is true if the account is currently locked.
	IsLocked bool

	// FailedAttempts is the number of failed attempts in the window.
	FailedAttempts int

	// RemainingAttempts is how many attempts remain before lockout.
	RemainingAttempts int

	// LockedUntil is when the lockout expires (only set if IsLocked).
	LockedUntil time.Time

	// LastAttempt is when the last failed attempt occurred.
	LastAttempt time.Time
}

// LockoutStore defines the storage interface for lockout state.
type LockoutStore interface {
	// RecordAttempt records a login attempt (success or failure).
	RecordAttempt(ctx context.Context, identifier string, success bool) error

	// GetStatus returns the current lockout status for an identifier.
	GetStatus(ctx context.Context, identifier string, cfg LockoutConfig) (LockoutStatus, error)

	// Lock explicitly locks an account.
	Lock(ctx context.Context, identifier string, until time.Time) error

	// Unlock explicitly unlocks an account.
	Unlock(ctx context.Context, identifier string) error

	// Reset clears all attempt history for an identifier.
	Reset(ctx context.Context, identifier string) error

	// Close releases resources.
	Close() error
}

// Lockout provides account lockout functionality.
type Lockout struct {
	store  LockoutStore
	config LockoutConfig
}

// NewLockout creates a new Lockout service.
func NewLockout(store LockoutStore, opts ...LockoutOption) *Lockout {
	l := &Lockout{
		store:  store,
		config: DefaultLockoutConfig(),
	}

	for _, opt := range opts {
		opt(l)
	}

	return l
}

// LockoutOption configures a Lockout service.
type LockoutOption func(*Lockout)

// WithLockoutConfig sets the lockout configuration.
func WithLockoutConfig(cfg LockoutConfig) LockoutOption {
	return func(l *Lockout) {
		l.config = cfg
	}
}

// WithMaxAttempts sets the maximum failed attempts before lockout.
func WithMaxAttempts(n int) LockoutOption {
	return func(l *Lockout) {
		l.config.MaxAttempts = n
	}
}

// WithLockoutDuration sets how long accounts stay locked.
func WithLockoutDuration(d time.Duration) LockoutOption {
	return func(l *Lockout) {
		l.config.LockoutDuration = d
	}
}

// normalizeIdentifier makes every spelling of an account's identifier count
// against the same lockout: case and surrounding space are not part of who
// someone is, and treating them as such lets an attacker restart the count
// by varying them.
func normalizeIdentifier(identifier string) string {
	return strings.ToLower(strings.TrimSpace(identifier))
}

// RecordFailure records a failed login attempt.
// Returns ErrAccountLocked if the account becomes locked.
func (l *Lockout) RecordFailure(ctx context.Context, identifier string) error {
	identifier = normalizeIdentifier(identifier)
	if err := l.store.RecordAttempt(ctx, identifier, false); err != nil {
		return err
	}

	status, err := l.store.GetStatus(ctx, identifier, l.config)
	if err != nil {
		return err
	}

	if status.FailedAttempts >= l.config.MaxAttempts {
		lockUntil := time.Now().Add(l.config.LockoutDuration)
		if err := l.store.Lock(ctx, identifier, lockUntil); err != nil {
			return err
		}
		return ErrAccountLocked
	}

	return nil
}

// RecordSuccess records a successful login and resets the attempt counter.
func (l *Lockout) RecordSuccess(ctx context.Context, identifier string) error {
	identifier = normalizeIdentifier(identifier)
	if err := l.store.RecordAttempt(ctx, identifier, true); err != nil {
		return err
	}
	return l.store.Reset(ctx, identifier)
}

// IsLocked checks if an account is currently locked.
func (l *Lockout) IsLocked(ctx context.Context, identifier string) (bool, error) {
	identifier = normalizeIdentifier(identifier)
	status, err := l.store.GetStatus(ctx, identifier, l.config)
	if err != nil {
		return false, err
	}
	return status.IsLocked, nil
}

// GetStatus returns the current lockout status.
func (l *Lockout) GetStatus(ctx context.Context, identifier string) (LockoutStatus, error) {
	identifier = normalizeIdentifier(identifier)
	return l.store.GetStatus(ctx, identifier, l.config)
}

// CheckAndRecord checks if locked, then records the attempt.
// This is the recommended method for login flows.
// Returns ErrAccountLocked if the account is locked (before or after the attempt).
//
// The check and the record are separate steps: concurrent logins all pass
// the check before any failure is recorded, so a burst of N parallel guesses
// gets up to N tries beyond MaxAttempts. Bound that with a rate limit per
// source address (see session/ratelimit) in front of the login.
func (l *Lockout) CheckAndRecord(ctx context.Context, identifier string, success bool) error {
	identifier = normalizeIdentifier(identifier)
	// Check if already locked
	locked, err := l.IsLocked(ctx, identifier)
	if err != nil {
		return err
	}
	if locked {
		return ErrAccountLocked
	}

	// Record the attempt
	if success {
		return l.RecordSuccess(ctx, identifier)
	}
	return l.RecordFailure(ctx, identifier)
}

// Unlock manually unlocks an account.
func (l *Lockout) Unlock(ctx context.Context, identifier string) error {
	identifier = normalizeIdentifier(identifier)
	return l.store.Unlock(ctx, identifier)
}

// Reset clears all lockout state for an identifier.
func (l *Lockout) Reset(ctx context.Context, identifier string) error {
	identifier = normalizeIdentifier(identifier)
	return l.store.Reset(ctx, identifier)
}

// Close releases resources.
func (l *Lockout) Close() error {
	return l.store.Close()
}

// MemoryLockoutStore is an in-memory implementation of LockoutStore.
type MemoryLockoutStore struct {
	attempts map[string][]time.Time
	locks    map[string]time.Time
	mu       sync.RWMutex
	closed   bool

	cleanupInterval time.Duration
	stopCleanup     chan struct{}
}

// MemoryLockoutOption configures MemoryLockoutStore.
type MemoryLockoutOption func(*MemoryLockoutStore)

// WithLockoutCleanupInterval sets the cleanup interval.
func WithLockoutCleanupInterval(d time.Duration) MemoryLockoutOption {
	return func(m *MemoryLockoutStore) {
		m.cleanupInterval = d
	}
}

// NewMemoryLockoutStore creates a new in-memory lockout store.
func NewMemoryLockoutStore(opts ...MemoryLockoutOption) *MemoryLockoutStore {
	m := &MemoryLockoutStore{
		attempts:        make(map[string][]time.Time),
		locks:           make(map[string]time.Time),
		cleanupInterval: 5 * time.Minute,
		stopCleanup:     make(chan struct{}),
	}

	for _, opt := range opts {
		opt(m)
	}

	go m.cleanup()

	return m
}

// RecordAttempt implements LockoutStore.
func (m *MemoryLockoutStore) RecordAttempt(ctx context.Context, identifier string, success bool) error {
	if success {
		return nil // Successful attempts don't need to be tracked
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageFailure
	}

	m.attempts[identifier] = append(m.attempts[identifier], time.Now())
	return nil
}

// GetStatus implements LockoutStore.
func (m *MemoryLockoutStore) GetStatus(ctx context.Context, identifier string, cfg LockoutConfig) (LockoutStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.closed {
		return LockoutStatus{}, ErrStorageFailure
	}

	now := time.Now()
	status := LockoutStatus{}

	// Check explicit lock
	if lockUntil, ok := m.locks[identifier]; ok {
		if now.Before(lockUntil) {
			status.IsLocked = true
			status.LockedUntil = lockUntil
		}
	}

	// Count recent failed attempts
	attempts := m.attempts[identifier]
	windowStart := now.Add(-cfg.AttemptWindow)

	for _, t := range attempts {
		if t.After(windowStart) {
			status.FailedAttempts++
			if t.After(status.LastAttempt) {
				status.LastAttempt = t
			}
		}
	}

	status.RemainingAttempts = cfg.MaxAttempts - status.FailedAttempts
	if status.RemainingAttempts < 0 {
		status.RemainingAttempts = 0
	}

	// Check if should be locked due to attempts
	if status.FailedAttempts >= cfg.MaxAttempts && !status.IsLocked {
		status.IsLocked = true
		status.LockedUntil = status.LastAttempt.Add(cfg.LockoutDuration)
		if now.After(status.LockedUntil) {
			status.IsLocked = false
			status.LockedUntil = time.Time{}
		}
	}

	return status, nil
}

// Lock implements LockoutStore.
func (m *MemoryLockoutStore) Lock(ctx context.Context, identifier string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageFailure
	}

	m.locks[identifier] = until
	return nil
}

// Unlock implements LockoutStore.
func (m *MemoryLockoutStore) Unlock(ctx context.Context, identifier string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrStorageFailure
	}

	delete(m.locks, identifier)
	delete(m.attempts, identifier)
	return nil
}

// Reset implements LockoutStore.
func (m *MemoryLockoutStore) Reset(ctx context.Context, identifier string) error {
	return m.Unlock(ctx, identifier)
}

// Close implements LockoutStore.
func (m *MemoryLockoutStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	close(m.stopCleanup)
	m.attempts = nil
	m.locks = nil
	return nil
}

func (m *MemoryLockoutStore) cleanup() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCleanup:
			return
		case <-ticker.C:
			m.cleanupExpired()
		}
	}
}

func (m *MemoryLockoutStore) cleanupExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}

	now := time.Now()
	threshold := now.Add(-time.Hour) // Clean up attempts older than 1 hour

	// Clean up old attempts
	for identifier, attempts := range m.attempts {
		var recent []time.Time
		for _, t := range attempts {
			if t.After(threshold) {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(m.attempts, identifier)
		} else {
			m.attempts[identifier] = recent
		}
	}

	// Clean up expired locks
	for identifier, lockUntil := range m.locks {
		if now.After(lockUntil) {
			delete(m.locks, identifier)
		}
	}
}
