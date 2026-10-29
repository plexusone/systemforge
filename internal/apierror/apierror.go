// Package apierror keeps internal error text out of API responses.
//
// Database, driver and provider errors can carry SQL, schema, constraint
// or host details. Handlers map the errors a client can act on to fixed
// messages and pass everything else to Internal (Huma operations) or Log
// (net/http handlers), which log the error and leave the client with a
// generic message.
package apierror

import (
	"context"
	"log/slog"

	"github.com/danielgtaylor/huma/v2"
)

// InternalMessage is the response text for an unexpected error.
const InternalMessage = "internal error"

// Log records err, an unexpected error of the operation op, with logger,
// or slog.Default() when logger is nil.
func Log(ctx context.Context, logger *slog.Logger, op string, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.ErrorContext(ctx, op, "error", err)
}

// Internal logs err like Log and returns a Huma 500 error whose body
// carries InternalMessage and no error text. Never pass err itself to a
// huma.Error constructor: Huma copies it into the response's errors list.
func Internal(ctx context.Context, logger *slog.Logger, op string, err error) huma.StatusError {
	Log(ctx, logger, op, err)
	return huma.Error500InternalServerError(InternalMessage)
}
