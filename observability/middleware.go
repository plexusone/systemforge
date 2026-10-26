package observability

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/plexusone/omniobserve/observops"
)

// RouteUnmatched is the http.route value recorded for a request that no
// route pattern matched.
const RouteUnmatched = "unmatched"

// Middleware creates HTTP middleware that traces requests and records metrics.
// It starts a span for each request and records method, route, status_code, and duration.
//
// The request URL is not recorded: its query string can carry OAuth
// authorization codes, state, API keys and other secrets, and its path can
// carry tokens such as invite tokens. The route is the matched pattern
// (http.ServeMux's Request.Pattern or chi's route pattern), or
// RouteUnmatched, which also keeps metric label cardinality bounded.
func (o *Observability) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Start span for request
			ctx, span := o.provider.Tracer().Start(r.Context(), SpanHTTPRequest,
				observops.WithSpanKind(observops.SpanKindServer),
				observops.WithSpanAttributes(requestAttributes(r)...),
			)
			defer span.End()

			// Wrap response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			// Inject trace ID into response headers
			sc := span.SpanContext()
			if sc.TraceID != "" {
				wrapped.Header().Set("X-Trace-ID", sc.TraceID)
			}

			// Process request with span context. The router records the
			// matched pattern on this request.
			req := r.WithContext(ctx)
			next.ServeHTTP(wrapped, req)
			route := routePattern(req)

			// Record span attributes
			duration := time.Since(start)
			span.SetAttributes(
				observops.Attribute("http.route", route),
				observops.Attribute("http.status_code", wrapped.statusCode),
				observops.Attribute("http.response_content_length", wrapped.bytesWritten),
			)

			// Set span status based on HTTP status code
			if wrapped.statusCode >= 400 {
				span.SetStatus(observops.StatusCodeError, http.StatusText(wrapped.statusCode))
			} else {
				span.SetStatus(observops.StatusCodeOK, "")
			}

			// Record request metric
			o.recordHTTPRequest(r.Context(), r.Method, route, wrapped.statusCode, duration)
		})
	}
}

// requestAttributes returns the span attributes recorded when a request
// starts. They hold no part of the URL path or query.
func requestAttributes(r *http.Request) []observops.KeyValue {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return []observops.KeyValue{
		observops.Attribute("http.method", r.Method),
		observops.Attribute("http.scheme", scheme),
		observops.Attribute("http.host", r.Host),
		observops.Attribute("http.user_agent", r.UserAgent()),
	}
}

// routePattern returns the route pattern that matched r, or RouteUnmatched.
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

// recordHTTPRequest records HTTP request metrics. route must be a route
// pattern, never a raw request path.
func (o *Observability) recordHTTPRequest(ctx context.Context, method, route string, statusCode int, duration time.Duration) {
	// Use the pre-created auth latency metric for now
	// In a more complete implementation, we'd have a dedicated HTTP request metric
	o.authLatency.Record(ctx, float64(duration.Milliseconds()), observops.WithAttributes(
		observops.Attribute("http.method", method),
		observops.Attribute("http.route", route),
		observops.Attribute("http.status_code", statusCode),
	))
}

// responseWriter wraps http.ResponseWriter to capture the status code and bytes written.
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

// WriteHeader captures the status code.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Write captures the number of bytes written.
func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// Unwrap returns the underlying ResponseWriter (for http.ResponseController).
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}
