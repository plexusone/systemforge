package systemauthsvc

import (
	"fmt"
	"io"
	"log/slog"
)

// NewLogger returns a slog logger writing to w at level ("debug", "info",
// "warn", "error"; default info) in format ("text" or "json"; default
// text).
func NewLogger(w io.Writer, level, format string) (*slog.Logger, error) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info", "":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	case "text", "":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid log format %q", format)
	}
}
