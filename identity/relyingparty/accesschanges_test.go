package relyingparty

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// memorySource is an AccessChangeSource over a slice.
type memorySource struct {
	mu      sync.Mutex
	changes []AccessChange
	err     error
	reads   []time.Time
}

func (s *memorySource) add(c ...AccessChange) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.changes = append(s.changes, c...)
}

func (s *memorySource) AccessChangesSince(_ context.Context, since time.Time) ([]AccessChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads = append(s.reads, since)
	if s.err != nil {
		return nil, s.err
	}
	var out []AccessChange
	for _, c := range s.changes {
		if c.ChangedAt.After(since) {
			out = append(out, c)
		}
	}
	return out, nil
}

func TestPollerRecordsNewChanges(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	cache := NewRevocationCache(WithClock(clk.now))
	src := &memorySource{}
	p := NewAccessChangePoller(src, cache, WithPollerClock(clk.now))

	// The first poll reads back one lifetime plus the margin.
	if err := p.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if want := clk.now().Add(-15*time.Minute - 30*time.Second); !src.reads[0].Equal(want) {
		t.Errorf("first read since %v, want %v", src.reads[0], want)
	}

	// A change made elsewhere shows up in the next poll.
	clk.advance(time.Second)
	src.add(AccessChange{PrincipalID: "kim", OrganizationID: "acme", ChangedAt: clk.now(), Reason: "membership_removed"})
	if cache.Accept("kim", "acme", clk.now().Add(-time.Minute)) == false {
		t.Fatal("refused before the poll saw the change")
	}
	clk.advance(time.Second)
	if err := p.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if cache.Accept("kim", "acme", clk.now().Add(-time.Minute)) {
		t.Error("the polled change was not recorded")
	}

	// A row that committed late, with an earlier timestamp, is still read:
	// the next read starts a margin behind the newest change.
	clk.advance(10 * time.Second)
	late := AccessChange{PrincipalID: "lee", ChangedAt: clk.now().Add(-5 * time.Second), Reason: "deactivated"}
	src.add(late)
	if err := p.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if cache.Accept("lee", "", clk.now().Add(-time.Minute)) {
		t.Error("a late-committed change was missed")
	}
}

func TestPollerErrorsKeepSuspectMode(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	cache := NewRevocationCache(WithClock(clk.now), WithSuspectStart())
	src := &memorySource{err: errors.New("database down")}
	p := NewAccessChangePoller(src, cache, WithPollerClock(clk.now))

	if err := p.Poll(ctx); err == nil {
		t.Fatal("a failing source returned no error")
	}
	if !cache.Suspect() {
		t.Error("a failed poll ended suspect mode")
	}
	src.mu.Lock()
	src.err = nil
	src.mu.Unlock()
	if err := p.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if cache.Suspect() {
		t.Error("the first successful poll did not end suspect mode")
	}
}

func TestPollIntervalIsBounded(t *testing.T) {
	for in, want := range map[time.Duration]time.Duration{
		0: time.Second, 100 * time.Millisecond: time.Second, 1500 * time.Millisecond: 1500 * time.Millisecond, time.Minute: 2 * time.Second,
	} {
		if got := NewAccessChangePoller(&memorySource{}, NewRevocationCache(), WithPollInterval(in)).interval; got != want {
			t.Errorf("interval %v = %v, want %v", in, got, want)
		}
	}
}

func TestPollerRunStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	src := &memorySource{}
	p := NewAccessChangePoller(src, NewRevocationCache())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	deadline := time.After(5 * time.Second)
	for {
		src.mu.Lock()
		n := len(src.reads)
		src.mu.Unlock()
		if n > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Run never polled")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// TestSuspectModeRefusesTokensIssuedBeforeTheCacheListened verifies the
// restart rule of ADR-010 decision 6.
func TestSuspectModeRefusesTokensIssuedBeforeTheCacheListened(t *testing.T) {
	clk := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	cache := NewRevocationCache(WithClock(clk.now), WithSuspectStart())
	start := clk.now()
	if !cache.Suspect() {
		t.Fatal("WithSuspectStart did not start suspect")
	}
	for name, tc := range map[string]struct {
		iat  time.Time
		want bool
	}{
		"issued before the restart": {start.Add(-time.Minute), false},
		"issued inside the margin":  {start.Add(10 * time.Second), false},
		"issued after the margin":   {start.Add(31 * time.Second), true},
	} {
		if got := cache.Accept("anyone", "", tc.iat); got != tc.want {
			t.Errorf("%s: Accept = %v, want %v", name, got, tc.want)
		}
	}
	if v := cache.ValidFrom("anyone", ""); !v.Equal(start.Add(30 * time.Second)) {
		t.Errorf("ValidFrom in suspect mode = %v", v)
	}

	// A replay rebuilds the cache and ends suspect mode: the old token is
	// accepted again unless a change names its principal.
	src := &memorySource{}
	src.add(AccessChange{PrincipalID: "kim", ChangedAt: start.Add(-time.Minute), Reason: "deactivated"})
	if err := Replay(context.Background(), src, cache); err != nil {
		t.Fatal(err)
	}
	if cache.Suspect() {
		t.Error("Replay left the cache suspect")
	}
	old := start.Add(-2 * time.Minute)
	if !cache.Accept("anyone", "", old) {
		t.Error("an unaffected principal's token is still refused after the replay")
	}
	if cache.Accept("kim", "", old) {
		t.Error("the replay did not record kim's deactivation")
	}
	if want := start.Add(-15*time.Minute - 30*time.Second); !src.reads[0].Equal(want) {
		t.Errorf("replay read since %v, want %v", src.reads[0], want)
	}
}

func TestReplayFailureStaysSuspect(t *testing.T) {
	cache := NewRevocationCache(WithSuspectStart())
	src := &memorySource{err: errors.New("down")}
	if err := Replay(context.Background(), src, cache); err == nil {
		t.Fatal("Replay hid the failure")
	}
	if !cache.Suspect() {
		t.Error("a failed replay ended suspect mode")
	}
}

func TestReplayWithRetryBacksOffUntilItSucceeds(t *testing.T) {
	cache := NewRevocationCache(WithSuspectStart())
	src := &memorySource{err: errors.New("down")}
	done := make(chan error, 1)
	go func() { done <- ReplayWithRetry(context.Background(), src, cache, nil) }()
	// Let the first attempt fail, then heal the source; the retry follows
	// after the one second backoff.
	deadline := time.After(10 * time.Second)
	for {
		src.mu.Lock()
		n := len(src.reads)
		src.mu.Unlock()
		if n > 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("no attempt made")
		case <-time.After(5 * time.Millisecond):
		}
	}
	src.mu.Lock()
	src.err = nil
	src.mu.Unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ReplayWithRetry did not recover")
	}
	if cache.Suspect() {
		t.Error("still suspect after a successful retry")
	}

	// A cancelled context stops the retries.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ReplayWithRetry(ctx, &memorySource{err: errors.New("down")}, NewRevocationCache(), nil); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled retry = %v", err)
	}
}

func TestRemoteAccessChangesSource(t *testing.T) {
	var gotAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		if r.URL.Path != AccessChangesPath {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "DPoP tok" || r.Header.Get("DPoP") == "" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		since, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("since"))
		if err != nil {
			http.Error(w, "bad since", http.StatusBadRequest)
			return
		}
		// Two pages: the first carries next_since.
		if since.Before(time.Date(2030, 1, 1, 0, 0, 1, 0, time.UTC)) {
			next := time.Date(2030, 1, 1, 0, 0, 1, 0, time.UTC)
			writeJSON(w, http.StatusOK, map[string]any{
				"changes":    []map[string]any{{"principal_id": "p1", "organization_id": "o1", "changed_at": next, "reason": "org_role_changed"}},
				"next_since": next,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"changes": []map[string]any{{"principal_id": "p2", "changed_at": since.Add(time.Second), "reason": "deactivated"}},
		})
	}))
	t.Cleanup(srv.Close)
	c := newTestClient(t, srv.URL, srv.Client(), Metadata{})
	token := func(context.Context) (string, error) { return "tok", nil }

	got, err := c.AccessChangesSource(token).AccessChangesSince(context.Background(), time.Date(2029, 12, 31, 0, 0, 0, 0, time.UTC))
	if err != nil || len(got) != 2 {
		t.Fatalf("changes = %+v, %v", got, err)
	}
	if got[0].PrincipalID != "p1" || got[0].OrganizationID != "o1" || got[0].Reason != "org_role_changed" || got[1].PrincipalID != "p2" || got[1].OrganizationID != "" {
		t.Errorf("changes = %+v", got)
	}
	if len(gotAuth) != 2 {
		t.Errorf("requests = %d, want 2 pages", len(gotAuth))
	}
	bad := func(context.Context) (string, error) { return "wrong", nil }
	if _, err := c.AccessChangesSource(bad).AccessChangesSince(context.Background(), time.Now()); err == nil {
		t.Error("a rejected token returned no error")
	}
	failing := func(context.Context) (string, error) { return "", errors.New("no token") }
	if _, err := c.AccessChangesSource(failing).AccessChangesSince(context.Background(), time.Now()); err == nil {
		t.Error("a token failure returned no error")
	}
}

func TestClientCredentialsTokenAsksForTheScope(t *testing.T) {
	var form map[string][]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("form: %v", err)
		}
		form = r.PostForm
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "cc-token", "token_type": "bearer", "expires_in": 600})
	}))
	t.Cleanup(srv.Close)
	c := newTestClient(t, "", srv.Client(), Metadata{TokenEndpoint: srv.URL})
	tok, err := c.ClientCredentialsToken("rp", "secret")(context.Background())
	if err != nil || tok != "cc-token" {
		t.Fatalf("token = %q, %v", tok, err)
	}
	if form["grant_type"][0] != "client_credentials" || form["scope"][0] != AccessChangesScope {
		t.Errorf("token request = %v", form)
	}
}
