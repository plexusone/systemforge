package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func requestFrom(remote string, forwarded ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for _, f := range forwarded {
		r.Header.Add("X-Forwarded-For", f)
	}
	return r
}

// TestIPKeyIgnoresForwardingHeaders verifies that a client cannot choose
// its rate-limit key, or someone else's, with headers.
func TestIPKeyIgnoresForwardingHeaders(t *testing.T) {
	key := IPKey()
	base := key(requestFrom("203.0.113.9:1111"))
	if base != "ip:203.0.113.9" {
		t.Fatalf("key = %q", base)
	}
	for name, r := range map[string]*http.Request{
		"rotated X-Forwarded-For": requestFrom("203.0.113.9:1111", "198.51.100.1"),
		"spoofed victim":          requestFrom("203.0.113.9:1111", "192.0.2.77, 10.0.0.1"),
		"another source port":     requestFrom("203.0.113.9:2222"),
	} {
		if got := key(r); got != base {
			t.Errorf("%s: key %q, want %q", name, got, base)
		}
	}
	r := requestFrom("203.0.113.9:1111")
	r.Header.Set("X-Real-IP", "192.0.2.77")
	if got := key(r); got != base {
		t.Errorf("X-Real-IP changed the key to %q", got)
	}
	if got := key(requestFrom("[2001:db8::1]:4444")); got != "ip:2001:db8::1" {
		t.Errorf("IPv6 key %q has a port or brackets", got)
	}
	if got := key(requestFrom("[::ffff:203.0.113.9]:80")); got != base {
		t.Errorf("IPv4-mapped key %q", got)
	}
	if got := key(requestFrom("garbage")); got != "ip:unknown" {
		t.Errorf("unparseable peer key %q", got)
	}
}

func TestForwardedClientIP(t *testing.T) {
	clientIP, err := ForwardedClientIP("10.0.0.0/8", "192.0.2.0/24")
	if err != nil {
		t.Fatalf("ForwardedClientIP: %v", err)
	}
	for _, tc := range []struct {
		name      string
		remote    string
		forwarded []string
		want      string
	}{
		{"direct client, header ignored", "203.0.113.9:1", []string{"198.51.100.1"}, "203.0.113.9"},
		{"one proxy", "10.0.0.5:1", []string{"198.51.100.1"}, "198.51.100.1"},
		{"two proxies", "10.0.0.5:1", []string{"198.51.100.1, 192.0.2.8"}, "198.51.100.1"},
		{"client forges the left of the chain", "10.0.0.5:1", []string{"192.0.2.77, 198.51.100.1"}, "198.51.100.1"},
		{"several header lines", "10.0.0.5:1", []string{"203.0.113.50", "198.51.100.1"}, "198.51.100.1"},
		{"garbage in the chain", "10.0.0.5:1", []string{"not-an-ip"}, "10.0.0.5"},
		{"no header", "10.0.0.5:1", nil, "10.0.0.5"},
		{"IPv6 client", "10.0.0.5:1", []string{"2001:db8::7"}, "2001:db8::7"},
	} {
		if got := clientIP(requestFrom(tc.remote, tc.forwarded...)); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if _, err := ForwardedClientIP(); err == nil {
		t.Error("no networks accepted")
	}
	if _, err := ForwardedClientIP("bogus"); err == nil {
		t.Error("a malformed network accepted")
	}
	key, err := ForwardedIPKey("10.0.0.0/8")
	if err != nil || key(requestFrom("10.0.0.5:1", "198.51.100.1")) != "ip:198.51.100.1" {
		t.Errorf("ForwardedIPKey = %v", err)
	}
}

func TestMemoryStorageBoundsItsKeys(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStorage(WithMaxKeys(3))
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	limit := PerMinute(5)
	for _, k := range []string{"a", "b", "c"} {
		if _, err := m.Allow(ctx, k, limit); err != nil {
			t.Fatalf("Allow(%s): %v", k, err)
		}
	}
	if _, err := m.Allow(ctx, "d", limit); !errors.Is(err, ErrTooManyKeys) {
		t.Errorf("a fourth key = %v, want ErrTooManyKeys", err)
	}
	// Tracked keys keep working while the store is full.
	if r, err := m.Allow(ctx, "a", limit); err != nil || !r.Allowed {
		t.Errorf("an existing key = %+v, %v", r, err)
	}
	// Expired windows make room.
	short := Limit{Rate: 1, Period: 20 * time.Millisecond, Burst: 1}
	m2 := NewMemoryStorage(WithMaxKeys(1))
	t.Cleanup(func() {
		if err := m2.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if _, err := m2.Allow(ctx, "x", short); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	time.Sleep(40 * time.Millisecond)
	if _, err := m2.Allow(ctx, "y", short); err != nil {
		t.Errorf("a new key after the old window ended: %v", err)
	}
}

// TestMemoryStorageExpiresByPeriod verifies that a window longer than an
// hour is not discarded early, which would reset its count.
func TestMemoryStorageExpiresByPeriod(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStorage()
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	day := Limit{Rate: 1, Period: 24 * time.Hour, Burst: 1}
	if _, err := m.Allow(ctx, "k", day); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	m.mu.Lock()
	m.windows["k"].startTime = time.Now().Add(-2 * time.Hour)
	m.mu.Unlock()
	m.cleanupExpired()
	if r, err := m.Allow(ctx, "k", day); err != nil || r.Allowed {
		t.Errorf("a day-long window reset after two hours: %+v, %v", r, err)
	}
}

func TestMemoryStorageAfterClose(t *testing.T) {
	m := NewMemoryStorage()
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := m.Allow(context.Background(), "k", PerMinute(1)); !errors.Is(err, ErrClosed) {
		t.Errorf("Allow after Close = %v, want ErrClosed", err)
	}
}

type failingStorage struct{}

func (failingStorage) Allow(context.Context, string, Limit) (Result, error) {
	return Result{}, errors.New("redis down")
}
func (failingStorage) Reset(context.Context, string) error { return nil }
func (failingStorage) Close() error                        { return nil }

// TestMiddlewareFailsClosed verifies that a storage outage does not switch
// the limits off unless the operator asked for that.
func TestMiddlewareFailsClosed(t *testing.T) {
	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	for _, tc := range []struct {
		name     string
		opts     []Option
		wantCode int
		reaches  bool
	}{
		{"default", nil, http.StatusServiceUnavailable, false},
		{"fail open", []Option{WithFailOpen()}, http.StatusOK, true},
	} {
		reached = false
		w := httptest.NewRecorder()
		New(failingStorage{}, tc.opts...).Middleware()(next).ServeHTTP(w, requestFrom("203.0.113.9:1"))
		if w.Code != tc.wantCode || reached != tc.reaches {
			t.Errorf("%s: status %d, reached %v", tc.name, w.Code, reached)
		}
	}
}
