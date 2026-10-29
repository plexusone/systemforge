package oauthcore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/ory/fosite"
)

// stackError formats like a pkg/errors value: %+v adds a stack trace with
// source paths.
type stackError struct{ msg string }

func (e stackError) Error() string { return e.msg }

// Format has no way to report a write error: fmt.Formatter returns
// nothing, and fmt records a failed write in its own result.
func (e stackError) Format(f fmt.State, verb rune) {
	out := e.msg
	if verb == 'v' && f.Flag('+') {
		out += "\ngithub.com/example/pkg.fn\n\t/src/pkg/file.go:42"
	}
	_, _ = f.Write([]byte(out)) // see above: the Formatter cannot return the error
}

func withStack(err error) error { return stackError{msg: err.Error()} }

func logOnce(level slog.Level, err error) string {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level}))
	logger.Warn("token request failed", ErrorAttr(context.Background(), logger, err))
	return buf.String()
}

func TestErrorAttrHasNoStackTrace(t *testing.T) {
	cause := withStack(errors.New("storage: no such code"))
	err := fosite.ErrInvalidGrant.WithWrap(cause).WithHint("The code is not valid.").WithDebug("debug detail")

	// The test's premise: %+v of the stack-carrying cause, as slog's text
	// handler formats an error value, prints a stack trace.
	if !strings.Contains(fmt.Sprintf("%+v", cause), ".go:") {
		t.Fatal("expected the cause to carry a stack trace")
	}

	for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
		out := logOnce(level, err)
		if strings.Contains(out, ".go:") || strings.Count(out, "\n") != 1 {
			t.Errorf("level %v: stack trace in log: %s", level, out)
		}
		for _, want := range []string{"error.code=invalid_grant", `error.hint="The code is not valid."`, "error.status=400"} {
			if !strings.Contains(out, want) {
				t.Errorf("level %v: %q missing from %s", level, want, out)
			}
		}
		hasCause := strings.Contains(out, "storage: no such code") && strings.Contains(out, "debug detail")
		if hasCause != (level == slog.LevelDebug) {
			t.Errorf("level %v: cause logged = %v: %s", level, hasCause, out)
		}
	}
}

func TestErrorAttrServerErrorKeepsCause(t *testing.T) {
	out := logOnce(slog.LevelInfo, fosite.ErrServerError.WithWrap(withStack(errors.New("database is down"))))
	if !strings.Contains(out, "database is down") || strings.Contains(out, ".go:") {
		t.Errorf("server error log: %s", out)
	}
}

func TestErrorAttrPlainError(t *testing.T) {
	out := logOnce(slog.LevelInfo, withStack(errors.New("plain failure")))
	if !strings.Contains(out, `error="plain failure"`) || strings.Contains(out, ".go:") {
		t.Errorf("plain error log: %s", out)
	}
	if got := ErrorCode(errors.New("x")); got != "server_error" {
		t.Errorf("ErrorCode(plain) = %q", got)
	}
	if got := ErrorCode(fmt.Errorf("wrapped: %w", fosite.ErrInvalidClient)); got != "invalid_client" {
		t.Errorf("ErrorCode(invalid_client) = %q", got)
	}
}
