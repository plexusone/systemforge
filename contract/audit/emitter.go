package audit

import (
	"context"
	"log/slog"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

// Outcomes of an event.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// NopEmitter discards every event. It is the default where an emitter is
// optional.
type NopEmitter struct{}

// Emit discards ev.
func (NopEmitter) Emit(context.Context, *Event) error { return nil }

// RequestID returns the ID chi's request-ID middleware gave the request
// ctx belongs to, or "" outside such a request.
func RequestID(ctx context.Context) string {
	return middleware.GetReqID(ctx)
}

// LogEmitter writes every event as one structured log record, a security
// event log for deployments without an audit store. Failures are logged
// at warning level, successes at info.
type LogEmitter struct {
	logger *slog.Logger
}

// NewLogEmitter returns a LogEmitter writing to logger, or to slog.Default
// when logger is nil.
func NewLogEmitter(logger *slog.Logger) *LogEmitter {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogEmitter{logger: logger}
}

// Emit logs ev under the message "security event".
func (e *LogEmitter) Emit(ctx context.Context, ev *Event) error {
	level := slog.LevelInfo
	if ev.Outcome == OutcomeFailure {
		level = slog.LevelWarn
	}
	attrs := []slog.Attr{
		slog.String("event_type", ev.EventType),
		slog.String("action", ev.Action),
		slog.String("outcome", ev.Outcome),
	}
	if a := actorAttrs(ev.Actor); len(a) > 0 {
		attrs = append(attrs, slog.Attr{Key: "actor", Value: slog.GroupValue(a...)})
	}
	if r := resourceAttrs(ev.Resource); len(r) > 0 {
		attrs = append(attrs, slog.Attr{Key: "resource", Value: slog.GroupValue(r...)})
	}
	if c := contextAttrs(ev.Context); len(c) > 0 {
		attrs = append(attrs, slog.Attr{Key: "context", Value: slog.GroupValue(c...)})
	}
	if len(ev.Details) > 0 {
		attrs = append(attrs, slog.Any("details", ev.Details))
	}
	e.logger.LogAttrs(ctx, level, "security event", attrs...)
	return nil
}

func actorAttrs(a Actor) []slog.Attr {
	var out []slog.Attr
	if a.ID != uuid.Nil {
		out = append(out, slog.String("id", a.ID.String()))
	}
	if a.Type != "" {
		out = append(out, slog.String("type", a.Type))
	}
	if a.Identifier != "" {
		out = append(out, slog.String("identifier", a.Identifier))
	}
	return out
}

func resourceAttrs(r Resource) []slog.Attr {
	var out []slog.Attr
	if r.Type != "" {
		out = append(out, slog.String("type", r.Type))
	}
	if r.ID != uuid.Nil {
		out = append(out, slog.String("id", r.ID.String()))
	}
	if r.Identifier != "" {
		out = append(out, slog.String("identifier", r.Identifier))
	}
	return out
}

// contextAttrs leaves out SessionID: some callers keep a session token
// there, and the log must not carry one.
func contextAttrs(c Context) []slog.Attr {
	var out []slog.Attr
	if c.TenantID != nil {
		out = append(out, slog.String("tenant_id", c.TenantID.String()))
	}
	if c.RequestID != "" {
		out = append(out, slog.String("request_id", c.RequestID))
	}
	if c.ClientIP != "" {
		out = append(out, slog.String("client_ip", c.ClientIP))
	}
	if c.UserAgent != "" {
		out = append(out, slog.String("user_agent", c.UserAgent))
	}
	return out
}
