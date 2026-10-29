package ocsfaudit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/grokify/ocsf-schema-go/ocsf/objects"

	"github.com/plexusone/systemforge/contract/audit"
)

func testProduct() objects.Product {
	return objects.Product{Name: DefaultProductName, VendorName: DefaultVendorName, Version: "v0.0.0-test"}
}

func reporter(name string) *objects.Reporter { return &objects.Reporter{Name: name} }

// syncBuffer is a bytes.Buffer safe for the writer goroutine and the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) lines(t *testing.T) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(b.buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// blockingWriter blocks every Write until release is closed.
type blockingWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	n       int
	mu      sync.Mutex
}

func newBlockingWriter() *blockingWriter {
	return &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	w.mu.Lock()
	w.n++
	w.mu.Unlock()
	return len(p), nil
}

func signIn() *audit.Event {
	ev := evt("systemauth.sign_in", "sign_in", audit.OutcomeSuccess, map[string]any{"method": "github"})
	return &ev
}

func logCapture() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	return slog.New(slog.NewJSONHandler(buf, nil)), buf
}

func TestEmitWritesOneLinePerEvent(t *testing.T) {
	out := &syncBuffer{}
	e := New(out, Options{Deployment: "prod-eu", ProductVersion: "v0.30.0"})
	for range 3 {
		if err := e.Emit(context.Background(), signIn()); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	lines := out.lines(t)
	if len(lines) != 3 {
		t.Fatalf("%d lines, want 3", len(lines))
	}
	v := strictValidator()
	out.mu.Lock()
	raw := out.buf.String()
	out.mu.Unlock()
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		validateOCSF(t, v, []byte(line))
	}
	md, ok := lines[0]["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata: %v", lines[0])
	}
	if rep, ok := md["reporter"].(map[string]any); !ok || rep["name"] != "prod-eu" {
		t.Errorf("reporter: %v", md["reporter"])
	}
	if p, ok := md["product"].(map[string]any); !ok || p["version"] != "v0.30.0" {
		t.Errorf("product: %v", md["product"])
	}
	if lines[0]["metadata"].(map[string]any)["uid"] == lines[1]["metadata"].(map[string]any)["uid"] { //nolint:forcetypeassert // checked above
		t.Error("events share a metadata.uid")
	}
}

func TestEmitDropsWhenBufferFull(t *testing.T) {
	w := newBlockingWriter()
	logger, logs := logCapture()
	e := New(w, Options{BufferSize: 2, Logger: logger})
	// The first event is taken by the writer, which blocks; two fill the
	// buffer; the rest are dropped.
	if err := e.Emit(context.Background(), signIn()); err != nil {
		t.Fatal(err)
	}
	<-w.started
	for range 5 {
		if err := e.Emit(context.Background(), signIn()); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.Dropped(); got != 3 {
		t.Errorf("Dropped = %d, want 3", got)
	}
	close(w.release)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if w.n != 3 {
		t.Errorf("%d events written, want 3", w.n)
	}
	// Emit logged nothing; Close's final report counts every drop.
	recs := logs.lines(t)
	if len(recs) != 1 {
		t.Fatalf("drops logged %d times, want once, by the report on Close: %v", len(recs), recs)
	}
	if recs[0]["level"] != "WARN" || recs[0]["dropped"] != float64(3) || recs[0]["dropped_total"] != float64(3) {
		t.Errorf("drop log: %v", recs[0])
	}
}

// blockingHandler is a slog handler whose Handle blocks until release is
// closed, standing in for a stuck log destination.
type blockingHandler struct {
	release chan struct{}
	handled atomic.Int64
}

func (h *blockingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *blockingHandler) Handle(context.Context, slog.Record) error {
	<-h.release
	h.handled.Add(1)
	return nil
}
func (h *blockingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *blockingHandler) WithGroup(string) slog.Handler      { return h }

// TestEmitDoesNotLog checks that Emit never calls the logger, so a stuck
// log destination cannot block the request: drops are only counted, and
// the reporter logs them later.
func TestEmitDoesNotLog(t *testing.T) {
	w := newBlockingWriter()
	h := &blockingHandler{release: make(chan struct{})}
	e := New(w, Options{BufferSize: 1, Logger: slog.New(h)})
	if err := e.Emit(context.Background(), signIn()); err != nil {
		t.Fatal(err)
	}
	<-w.started
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 10 {
			if err := e.Emit(context.Background(), signIn()); err != nil {
				t.Error(err)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Emit blocked on the logger")
	}
	if e.Dropped() != 9 {
		t.Errorf("Dropped = %d, want 9", e.Dropped())
	}
	close(h.release)
	close(w.release)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if h.handled.Load() == 0 {
		t.Error("drops never reported")
	}
}

// TestReportLogsPeriodically checks that the reporter logs drops while the
// emitter runs, not only on Close.
func TestReportLogsPeriodically(t *testing.T) {
	logger, logs := logCapture()
	w := newBlockingWriter()
	e := newEmitter(w, Options{BufferSize: 1, Logger: logger}, 10*time.Millisecond)
	for range 3 {
		if err := e.Emit(context.Background(), signIn()); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(logs.lines(t)) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	recs := logs.lines(t)
	if len(recs) == 0 || recs[0]["level"] != "WARN" || recs[0]["dropped_total"] == nil {
		t.Fatalf("no drop report while running: %v", recs)
	}
	close(w.release)
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

// tearingWriter fails its first Write after writing part of the line, as
// a full disk can, and writes whole lines after that.
type tearingWriter struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	tore bool
}

func (w *tearingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.tore {
		w.tore = true
		w.buf.Write(p[:len(p)/2])
		return len(p) / 2, errors.New("no space left on device")
	}
	return w.buf.Write(p)
}

// TestTornLineDoesNotCorruptTheNext checks that after a Write leaves a
// partial line, the next event still lands on a line of its own.
func TestTornLineDoesNotCorruptTheNext(t *testing.T) {
	logger, _ := logCapture()
	w := &tearingWriter{}
	e := New(w, Options{Logger: logger})
	for range 3 {
		if err := e.Emit(context.Background(), signIn()); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(w.buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("%d lines, want the torn one and two whole ones: %q", len(lines), w.buf.String())
	}
	if json.Valid([]byte(lines[0])) {
		t.Error("the torn line parses as JSON")
	}
	for _, line := range lines[1:] {
		if !json.Valid([]byte(line)) {
			t.Errorf("line after the torn one is not JSON: %q", line)
		}
	}
	if e.WriteFailures() != 1 {
		t.Errorf("WriteFailures = %d, want 1", e.WriteFailures())
	}
}

// shortWriter reports writing one byte less than asked, without an error.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

// TestShortWriteIsAFailure checks that a Write reporting fewer bytes than
// the line without an error counts as a failure.
func TestShortWriteIsAFailure(t *testing.T) {
	logger, logs := logCapture()
	e := New(shortWriter{}, Options{Logger: logger})
	if err := e.Emit(context.Background(), signIn()); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if e.WriteFailures() != 1 {
		t.Errorf("WriteFailures = %d, want 1", e.WriteFailures())
	}
	recs := logs.lines(t)
	if len(recs) != 1 || recs[0]["error"] != io.ErrShortWrite.Error() {
		t.Errorf("short write log: %v", recs)
	}
}

// TestSyncUnsupported checks which Sync errors mean the file cannot be
// synced rather than a failure.
func TestSyncUnsupported(t *testing.T) {
	for _, err := range []error{syscall.EINVAL, syscall.ENOTSUP, syscall.ENOTTY, &os.PathError{Op: "sync", Path: "/dev/stdout", Err: syscall.ENOTTY}} {
		if !syncUnsupported(err) {
			t.Errorf("%v: want unsupported", err)
		}
	}
	for _, err := range []error{syscall.EBADF, syscall.EIO, errors.New("other")} {
		if syncUnsupported(err) {
			t.Errorf("%v: want a failure", err)
		}
	}
}

func TestCloseDrainsAndFlushes(t *testing.T) {
	var out bytes.Buffer
	bw := bufio.NewWriterSize(&out, 1<<20)
	e := New(bw, Options{BufferSize: 64})
	for range 50 {
		if err := e.Emit(context.Background(), signIn()); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out.String(), "\n"); n != 50 {
		t.Errorf("%d lines after Close, want 50", n)
	}
	if e.Dropped() != 0 {
		t.Errorf("Dropped = %d", e.Dropped())
	}
	// Idempotent.
	if err := e.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestEmitAfterCloseDrops(t *testing.T) {
	out := &syncBuffer{}
	logger, _ := logCapture()
	e := New(out, Options{Logger: logger})
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.Emit(context.Background(), signIn()); err != nil {
		t.Fatalf("Emit after Close returned %v", err)
	}
	if e.Dropped() != 1 {
		t.Errorf("Dropped = %d, want 1", e.Dropped())
	}
	if len(out.lines(t)) != 0 {
		t.Error("event written after Close")
	}
}

type failingWriter struct{ err error }

func (f failingWriter) Write([]byte) (int, error) { return 0, f.err }
func (f failingWriter) Flush() error              { return f.err }

func TestWriteErrorIsLogged(t *testing.T) {
	logger, logs := logCapture()
	boom := errors.New("disk full")
	e := New(failingWriter{boom}, Options{Logger: logger})
	for range 3 {
		if err := e.Emit(context.Background(), signIn()); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); !errors.Is(err, boom) {
		t.Errorf("Close = %v, want the flush error", err)
	}
	if e.WriteFailures() == 0 {
		t.Error("no write failure counted")
	}
	recs := logs.lines(t)
	if len(recs) != 1 || recs[0]["level"] != "ERROR" || recs[0]["error"] != "disk full" {
		t.Errorf("write failure log (rate limited to one): %v", recs)
	}
}

func TestEmitNilEvent(t *testing.T) {
	logger, logs := logCapture()
	out := &syncBuffer{}
	e := New(out, Options{Logger: logger})
	if err := e.Emit(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if len(out.lines(t)) != 0 || len(logs.lines(t)) != 0 || e.Dropped() != 0 || e.EncodeFailures() != 0 {
		t.Error("a nil event was written, logged or counted")
	}
}

func TestConcurrentEmit(t *testing.T) {
	out := &syncBuffer{}
	e := New(out, Options{BufferSize: 10000})
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 100 {
				ev := evt("organization.membership", "added", audit.OutcomeSuccess, map[string]any{"role": fmt.Sprintf("r%d-%d", g, i)})
				if err := e.Emit(context.Background(), &ev); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	// Close may race with late emits only after they finish here.
	wg.Wait()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if n := uint64(len(out.lines(t))) + e.Dropped(); n != 800 {
		t.Errorf("written+dropped = %d, want 800", n)
	}
}

func TestConcurrentEmitAndClose(t *testing.T) {
	out := &syncBuffer{}
	e := New(out, Options{BufferSize: 16, Logger: slog.New(slog.DiscardHandler)})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if err := e.Emit(context.Background(), signIn()); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if n := uint64(len(out.lines(t))) + e.Dropped(); n != 800 {
		t.Errorf("written+dropped = %d, want 800", n)
	}
}

// TestAppendModeFile is the host wiring the documentation shows: an
// append-mode file, closed after the emitter.
func TestAppendModeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security-events.ocsf.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: a file in the test's temporary directory
	if err != nil {
		t.Fatal(err)
	}
	e := New(f, Options{Deployment: "test"})
	if err := e.Emit(context.Background(), signIn()); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G304: a file the test created
	if err != nil {
		t.Fatal(err)
	}
	validateOCSF(t, strictValidator(), bytes.TrimSpace(data))
}

func TestMultiEmitterWithLogEmitter(t *testing.T) {
	out := &syncBuffer{}
	e := New(out, Options{})
	logger, logs := logCapture()
	m := audit.NewMultiEmitter(audit.NewLogEmitter(logger), e)
	if err := m.Emit(context.Background(), signIn()); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if len(out.lines(t)) != 1 || len(logs.lines(t)) != 1 {
		t.Error("each emitter should have the event once")
	}
}

// tearThenFailWriter tears its first line, fails its second Write without
// writing anything, and writes whole lines after that.
type tearThenFailWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	calls int
}

func (w *tearThenFailWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	switch w.calls {
	case 1:
		w.buf.Write(p[:len(p)/2])
		return len(p) / 2, errors.New("no space left on device")
	case 2:
		return 0, errors.New("no space left on device")
	}
	return w.buf.Write(p)
}

// TestTornLineSurvivesAnEmptyFailedWrite checks that a Write failing
// without writing anything after a torn line keeps the next event off the
// torn line.
func TestTornLineSurvivesAnEmptyFailedWrite(t *testing.T) {
	logger, _ := logCapture()
	w := &tearThenFailWriter{}
	e := New(w, Options{Logger: logger})
	for range 3 {
		if err := e.Emit(context.Background(), signIn()); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(w.buf.String(), "\n"), "\n")
	if len(lines) != 2 || json.Valid([]byte(lines[0])) || !json.Valid([]byte(lines[1])) {
		t.Fatalf("want the torn line, then one whole line; got %q", w.buf.String())
	}
	if e.WriteFailures() != 2 {
		t.Errorf("WriteFailures = %d, want 2", e.WriteFailures())
	}
}
