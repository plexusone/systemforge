package ocsfaudit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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
	recs := logs.lines(t)
	if len(recs) != 1 {
		t.Fatalf("drops logged %d times, want once (rate limited): %v", len(recs), recs)
	}
	if recs[0]["level"] != "WARN" || recs[0]["dropped"] != float64(1) || recs[0]["dropped_total"] != float64(1) {
		t.Errorf("drop log: %v", recs[0])
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

func TestEmitNeverFailsOnEncodingAndUsesContextLogger(t *testing.T) {
	ctxLogger, ctxLogs := logCapture()
	out := &syncBuffer{}
	e := New(out, Options{LoggerFromContext: func(context.Context) *slog.Logger { return ctxLogger }})
	defer func() {
		if err := e.Close(); err != nil {
			t.Error(err)
		}
	}()
	// Every value an event can carry encodes; a nil event is ignored.
	if err := e.Emit(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := e.ctxLogger(context.Background()); got != ctxLogger {
		t.Error("context logger not used")
	}
	if len(ctxLogs.lines(t)) != 0 {
		t.Error("unexpected log")
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
