package ratelimit

import (
	"context"
	"errors"
	"sync"
	"time"
)

// MemoryStorage is an in-memory rate limit storage using sliding window algorithm.
// Suitable for single-instance deployments and development/testing.
type MemoryStorage struct {
	windows map[string]*slidingWindow
	mu      sync.RWMutex
	closed  bool

	// cleanupInterval controls how often expired windows are cleaned up.
	cleanupInterval time.Duration
	stopCleanup     chan struct{}

	// maxKeys bounds the number of tracked keys.
	maxKeys int
}

type slidingWindow struct {
	count     int
	startTime time.Time
	period    time.Duration
	mu        sync.Mutex
}

// expired reports whether the window has ended, so a new request would
// start a fresh one and the old count no longer matters.
func (w *slidingWindow) expired(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return now.After(w.startTime.Add(w.period))
}

// DefaultMaxKeys is the number of keys MemoryStorage tracks by default.
const DefaultMaxKeys = 100_000

// ErrClosed is returned by a closed storage.
var ErrClosed = errors.New("ratelimit: storage closed")

// ErrTooManyKeys is returned when a new key arrives while the storage is
// tracking its maximum number of live keys. Callers should treat it as a
// refusal: keys are attacker-influenced on pre-authentication endpoints,
// and admitting them without bound would exhaust memory.
var ErrTooManyKeys = errors.New("ratelimit: too many tracked keys")

// WithMaxKeys sets the number of keys the storage tracks at once (default
// DefaultMaxKeys). Expired windows are discarded to make room first.
func WithMaxKeys(n int) MemoryOption {
	return func(m *MemoryStorage) {
		if n > 0 {
			m.maxKeys = n
		}
	}
}

// MemoryOption configures MemoryStorage.
type MemoryOption func(*MemoryStorage)

// WithCleanupInterval sets the interval for cleaning up expired windows.
func WithCleanupInterval(d time.Duration) MemoryOption {
	return func(m *MemoryStorage) {
		m.cleanupInterval = d
	}
}

// NewMemoryStorage creates a new in-memory rate limit storage.
func NewMemoryStorage(opts ...MemoryOption) *MemoryStorage {
	m := &MemoryStorage{
		windows:         make(map[string]*slidingWindow),
		cleanupInterval: 5 * time.Minute,
		stopCleanup:     make(chan struct{}),
		maxKeys:         DefaultMaxKeys,
	}

	for _, opt := range opts {
		opt(m)
	}

	// Start background cleanup goroutine
	go m.cleanup()

	return m
}

// Allow implements Storage.Allow using a sliding window algorithm.
func (m *MemoryStorage) Allow(ctx context.Context, key string, limit Limit) (Result, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return Result{}, ErrClosed
	}
	window, exists := m.windows[key]
	if !exists {
		if len(m.windows) >= m.maxKeys {
			m.evictExpiredLocked(time.Now())
		}
		if len(m.windows) >= m.maxKeys {
			m.mu.Unlock()
			return Result{}, ErrTooManyKeys
		}
		window = &slidingWindow{
			startTime: time.Now(),
			period:    limit.Period,
		}
		m.windows[key] = window
	}
	m.mu.Unlock()

	window.mu.Lock()
	defer window.mu.Unlock()

	now := time.Now()
	window.period = limit.Period
	windowEnd := window.startTime.Add(limit.Period)

	// Check if we're in a new window
	if now.After(windowEnd) {
		window.count = 0
		window.startTime = now
		windowEnd = now.Add(limit.Period)
	}

	burst := limit.Burst
	if burst == 0 {
		burst = limit.Rate
	}

	// Check if under limit
	if window.count < burst {
		window.count++
		return Result{
			Allowed:   true,
			Remaining: burst - window.count,
			ResetAt:   windowEnd,
		}, nil
	}

	// Rate limited
	retryAfter := windowEnd.Sub(now)
	if retryAfter < 0 {
		retryAfter = 0
	}

	return Result{
		Allowed:    false,
		Remaining:  0,
		ResetAt:    windowEnd,
		RetryAfter: retryAfter,
	}, nil
}

// Reset implements Storage.Reset.
func (m *MemoryStorage) Reset(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.windows, key)
	return nil
}

// Close implements Storage.Close.
func (m *MemoryStorage) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}

	m.closed = true
	close(m.stopCleanup)
	m.windows = nil
	return nil
}

// cleanup periodically removes expired windows to prevent memory growth.
func (m *MemoryStorage) cleanup() {
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

func (m *MemoryStorage) cleanupExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return
	}
	m.evictExpiredLocked(time.Now())
}

// evictExpiredLocked drops windows whose period has ended; a request after
// that would start a fresh window anyway. The caller holds m.mu.
func (m *MemoryStorage) evictExpiredLocked(now time.Time) {
	for key, window := range m.windows {
		if window.expired(now) {
			delete(m.windows, key)
		}
	}
}
