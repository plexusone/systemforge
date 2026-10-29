package ocsfaudit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/grokify/ocsf-schema-go/ocsf/objects"

	"github.com/plexusone/systemforge/contract/audit"
)

// Defaults of Options.
const (
	DefaultProductName = "SystemForge"
	DefaultVendorName  = "PlexusOne"
	DefaultBufferSize  = 1024
)

// reportInterval is how often the reporter logs the events dropped or
// left unencoded since its last report, and how often at most failing
// writes are logged; each record says how many occurred.
const reportInterval = time.Minute

// modulePath is SystemForge's module, whose version is the default
// product version.
const modulePath = "github.com/plexusone/systemforge"

// Options configure an Emitter.
type Options struct {
	// ProductName is metadata.product.name, the product that produced
	// the events. Default DefaultProductName.
	ProductName string

	// ProductVersion is metadata.product.version. Default: the version of
	// the SystemForge module the binary was built with, when known.
	ProductVersion string

	// VendorName is metadata.product.vendor_name. Default
	// DefaultVendorName.
	VendorName string

	// Deployment names this deployment, such as "prod-eu", as
	// metadata.reporter.name, so the events of several deployments
	// collected in one place can be told apart. Optional.
	Deployment string

	// BufferSize is how many events wait to be written before Emit drops
	// new ones. Default DefaultBufferSize.
	BufferSize int

	// Logger receives write failures and the counts of dropped and
	// unencodable events. It is called from the emitter's own goroutines,
	// never from Emit. Default slog.Default().
	Logger *slog.Logger
}

// Emitter is an audit.Emitter writing every event as one line of OCSF
// JSON. Emit never blocks and never logs: it maps the event and queues
// the line; a single goroutine writes the queue in order. When the queue
// is full the event is dropped and counted (Dropped), and a reporter
// goroutine logs the count once a minute. Close drains the queue.
type Emitter struct {
	w      io.Writer
	logger *slog.Logger
	mapper mapper

	mu     sync.RWMutex // guards closed and sends on queue
	closed bool
	queue  chan []byte
	done   chan struct{}

	stopReport chan struct{}
	reported   chan struct{}
	interval   time.Duration

	closeOnce sync.Once
	closeErr  error

	dropped     atomic.Uint64
	encodeFails atomic.Uint64
	writeLog    rateLog
	writeFails  atomic.Uint64
}

var _ audit.Emitter = (*Emitter)(nil)

// New returns an Emitter writing to w and starts its writer goroutine.
// The caller closes it with Close, after which it closes nothing of w's:
// w stays the caller's. Each event is one Write of one line, so an
// *os.File opened with os.O_APPEND gets whole lines.
func New(w io.Writer, opts Options) *Emitter {
	return newEmitter(w, opts, reportInterval)
}

// newEmitter is New with the reporter's interval, which tests shorten.
func newEmitter(w io.Writer, opts Options, interval time.Duration) *Emitter {
	if w == nil {
		panic("ocsfaudit: New with a nil writer")
	}
	if opts.ProductName == "" {
		opts.ProductName = DefaultProductName
	}
	if opts.VendorName == "" {
		opts.VendorName = DefaultVendorName
	}
	if opts.ProductVersion == "" {
		opts.ProductVersion = moduleVersion()
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = DefaultBufferSize
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	e := &Emitter{
		w:      w,
		logger: opts.Logger,
		mapper: mapper{
			product: objects.Product{Name: opts.ProductName, VendorName: opts.VendorName, Version: opts.ProductVersion},
			now:     time.Now,
			newUID:  func() string { return uuid.NewString() },
		},
		queue:      make(chan []byte, opts.BufferSize),
		done:       make(chan struct{}),
		stopReport: make(chan struct{}),
		reported:   make(chan struct{}),
		interval:   interval,
	}
	if opts.Deployment != "" {
		e.mapper.reporter = &objects.Reporter{Name: opts.Deployment}
	}
	go e.run()
	go e.report()
	return e
}

// moduleVersion returns the version of the SystemForge module in the
// running binary's build information, or "".
func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	if info.Main.Path == modulePath && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	for _, dep := range info.Deps {
		if dep.Path == modulePath {
			return dep.Version
		}
	}
	return ""
}

// Emit maps ev to OCSF and queues it for writing. It does not keep ev. It
// returns nil whatever happens, and it neither blocks nor logs: an event
// that cannot be encoded or queued is counted, and the reporter
// goroutine logs the counts, so recording an event never fails or delays
// the request that caused it.
func (e *Emitter) Emit(_ context.Context, ev *audit.Event) error {
	if ev == nil {
		return nil
	}
	line, err := json.Marshal(e.mapper.toOCSF(ev))
	if err != nil {
		e.encodeFails.Add(1)
		return nil
	}
	line = append(line, '\n')

	e.mu.RLock()
	queued := false
	if !e.closed {
		select {
		case e.queue <- line:
			queued = true
		default:
		}
	}
	e.mu.RUnlock()
	if !queued {
		e.dropped.Add(1)
	}
	return nil
}

// Dropped returns how many events were dropped because the buffer was
// full or the emitter was closed.
func (e *Emitter) Dropped() uint64 { return e.dropped.Load() }

// WriteFailures returns how many events failed to be written.
func (e *Emitter) WriteFailures() uint64 { return e.writeFails.Load() }

// EncodeFailures returns how many events could not be encoded as JSON.
func (e *Emitter) EncodeFailures() uint64 { return e.encodeFails.Load() }

// report logs, every interval and once more when Close stops it, how many
// events were dropped or could not be encoded since its last record.
func (e *Emitter) report() {
	defer close(e.reported)
	t := time.NewTicker(e.interval)
	defer t.Stop()
	var dropped, encodeFails uint64
	flush := func() {
		d, f := e.dropped.Load(), e.encodeFails.Load()
		if d > dropped {
			e.logger.Warn("ocsfaudit: dropped security events: the buffer is full or the emitter is closed",
				"dropped", d-dropped, "dropped_total", d)
		}
		if f > encodeFails {
			e.logger.Error("ocsfaudit: security events could not be encoded",
				"failures", f-encodeFails, "failures_total", f)
		}
		dropped, encodeFails = d, f
	}
	for {
		select {
		case <-t.C:
			flush()
		case <-e.stopReport:
			flush()
			return
		}
	}
}

// run writes the queue until Close closes it, flushing the writer
// whenever the queue is empty. A Write that fails part-way, or reports
// writing less than the line without an error, may leave a partial line
// behind; the next line then starts with a newline, so the damage stays
// on that one line and every following line is whole JSON.
func (e *Emitter) run() {
	defer close(e.done)
	torn := false
	for line := range e.queue {
		if torn {
			line = append([]byte{'\n'}, line...)
		}
		n, err := e.w.Write(line)
		if err == nil && n < len(line) {
			err = io.ErrShortWrite
		}
		torn = err != nil && n > 0 && n < len(line)
		if err != nil {
			e.writeFailed(err)
		}
		if len(e.queue) == 0 {
			if err := flush(e.w); err != nil {
				e.writeFailed(err)
			}
		}
	}
}

func (e *Emitter) writeFailed(err error) {
	total := e.writeFails.Add(1)
	if n, ok := e.writeLog.due(); ok {
		e.logger.Error("ocsfaudit: writing security events", "error", err.Error(), "failures", n, "failures_total", total)
	}
}

// flusher is a writer that buffers, such as *bufio.Writer.
type flusher interface{ Flush() error }

// syncer is a writer that can commit to storage, such as *os.File.
type syncer interface{ Sync() error }

func flush(w io.Writer) error {
	if f, ok := w.(flusher); ok {
		return f.Flush()
	}
	return nil
}

// Close stops accepting events, writes those queued, flushes the writer
// when it buffers (Flush) and commits it to storage when it can (Sync).
// It does not close the writer. Events emitted after Close are dropped
// and counted. Close is safe to call more than once; later calls return
// the first one's result.
func (e *Emitter) Close() error {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		close(e.queue)
		e.mu.Unlock()
		<-e.done
		close(e.stopReport)
		<-e.reported
		var errs []error
		if err := flush(e.w); err != nil {
			errs = append(errs, err)
		}
		if s, ok := e.w.(syncer); ok {
			if err := s.Sync(); err != nil && !syncUnsupported(err) {
				errs = append(errs, err)
			}
		}
		e.closeErr = errors.Join(errs...)
	})
	return e.closeErr
}

// syncUnsupported reports whether err is a Sync refused because the file
// cannot be synced, such as standard output on a pipe (EINVAL on Linux)
// or a terminal (ENOTTY on macOS): there is nothing to commit, so it is
// not a failure. Other errors, such as EBADF, are failures.
func syncUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.ENOTTY)
}

// rateLog decides when a repeated problem is logged: at most once per
// reportInterval, reporting how many occurred since.
type rateLog struct {
	mu      sync.Mutex
	last    time.Time
	pending uint64
}

// due counts one occurrence and reports, when it is time to log, how many
// occurred since the last log.
func (r *rateLog) due() (uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending++
	now := time.Now()
	if !r.last.IsZero() && now.Sub(r.last) < reportInterval {
		return 0, false
	}
	n := r.pending
	r.pending, r.last = 0, now
	return n, true
}
