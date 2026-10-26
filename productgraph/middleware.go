package productgraph

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// RouteUnmatched is the path recorded for a request that no route pattern
// matched.
const RouteUnmatched = "unmatched"

// routePattern returns the route pattern that matched r, or RouteUnmatched.
// The raw request path is never returned, because it can carry tokens and
// is unbounded.
func routePattern(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		if p := rctx.RoutePattern(); p != "" {
			return p
		}
	}
	return RouteUnmatched
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *responseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// RequestTrackerMiddleware creates middleware that tracks HTTP requests to ProductGraph.
// It records api.response events with method, route pattern, status code,
// and duration. The route is the pattern http.ServeMux or chi matched, or
// RouteUnmatched, never the request path.
func RequestTrackerMiddleware(client *Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if client == nil || !client.IsEnabled() {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(ww, r)

			duration := time.Since(start)

			// Track the request asynchronously
			if err := client.TrackAPICall(
				r.Context(),
				r.Method,
				routePattern(r),
				ww.status,
				duration,
			); err != nil {
				slog.WarnContext(r.Context(), "productgraph: tracking request", "error", err)
			}
		})
	}
}

// ChainMiddleware chains correlation and request tracking middleware.
// This is a convenience function that applies both middlewares in the correct order:
// 1. CorrelationMiddleware - extracts session/request IDs
// 2. RequestTrackerMiddleware - tracks API calls with correlation
func ChainMiddleware(client *Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Apply in reverse order so correlation runs first
		return CorrelationMiddleware(
			RequestTrackerMiddleware(client)(next),
		)
	}
}
