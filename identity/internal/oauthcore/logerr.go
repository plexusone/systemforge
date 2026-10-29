package oauthcore

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/ory/fosite"
)

// ErrorAttr returns an "error" log attribute summarizing err without its
// stack trace. slog's text handler formats error values with %+v, and
// Fosite's errors (and the pkg/errors values they wrap) print a full stack
// trace with source paths under %+v; this attribute holds only strings.
//
// For an RFC 6749 error the group holds the error code, description, hint
// and HTTP status. A server error (5xx) adds the wrapped cause's message; a
// client error adds the cause's message and Fosite's debug text only when
// logger is enabled at debug level, since they describe the client's
// mistake in detail. Any other error is logged by its message.
func ErrorAttr(ctx context.Context, logger *slog.Logger, err error) slog.Attr {
	if err == nil {
		return slog.String("error", "")
	}
	var rfc *fosite.RFC6749Error
	if !errors.As(err, &rfc) {
		return slog.String("error", err.Error())
	}
	attrs := []any{slog.String("code", rfc.ErrorField)}
	if rfc.DescriptionField != "" {
		attrs = append(attrs, slog.String("description", rfc.DescriptionField))
	}
	if rfc.HintField != "" {
		attrs = append(attrs, slog.String("hint", rfc.HintField))
	}
	if rfc.CodeField != 0 {
		attrs = append(attrs, slog.Int("status", rfc.CodeField))
	}
	serverError := rfc.CodeField >= http.StatusInternalServerError
	debug := logger != nil && logger.Enabled(ctx, slog.LevelDebug)
	if serverError || debug {
		if cause := rfc.Cause(); cause != nil && cause != error(rfc) {
			attrs = append(attrs, slog.String("cause", cause.Error()))
		}
	}
	if debug && rfc.DebugField != "" {
		attrs = append(attrs, slog.String("debug", rfc.DebugField))
	}
	return slog.Group("error", attrs...)
}

// ErrorCode returns the RFC 6749 error code of err, or "server_error" when
// err is not an OAuth error.
func ErrorCode(err error) string {
	var rfc *fosite.RFC6749Error
	if errors.As(err, &rfc) {
		return rfc.ErrorField
	}
	return fosite.ErrServerError.ErrorField
}
