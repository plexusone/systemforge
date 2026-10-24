// Package productgraph provides a client for sending events to ProductGraph
// and middleware for frontend-backend correlation.
package productgraph

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// ContextKey is used for storing correlation values in context.
type ContextKey string

const (
	// SessionIDKey is the context key for session ID.
	SessionIDKey ContextKey = "productgraph.session_id"
	// RequestIDKey is the context key for request ID.
	RequestIDKey ContextKey = "productgraph.request_id"
	// UserIDKey is the context key for user ID.
	UserIDKey ContextKey = "productgraph.user_id"
)

const (
	// HeaderSessionID is the HTTP header for session ID from frontend.
	HeaderSessionID = "X-Session-ID"
	// HeaderRequestID is the HTTP header for request ID.
	HeaderRequestID = "X-Request-ID"
	// HeaderUserID is the HTTP header a frontend may send with its user ID.
	//
	// Deprecated: CorrelationMiddleware no longer reads it, because any
	// caller could attribute events to another user. Set the user ID from
	// the authenticated session with WithUserID instead.
	HeaderUserID = "X-User-ID"
)

// CorrelationMiddleware extracts correlation headers from incoming requests
// and injects them into the request context. It also generates a request ID
// if not provided and echoes it back in the response.
//
// It does not take the user ID from the request: a header is set by the
// caller and proves nothing. After authentication, set the user ID from
// the verified session or token with WithUserID.
func CorrelationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Extract session ID from header
		if sessionID := r.Header.Get(HeaderSessionID); sessionID != "" {
			ctx = context.WithValue(ctx, SessionIDKey, sessionID)
		}

		// Extract or generate request ID
		requestID := r.Header.Get(HeaderRequestID)
		if requestID == "" {
			requestID = uuid.New().String()
		}
		ctx = context.WithValue(ctx, RequestIDKey, requestID)

		// Echo request ID back in response
		w.Header().Set(HeaderRequestID, requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SessionIDFromContext extracts the session ID from context.
// Returns empty string if not present.
func SessionIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(SessionIDKey).(string); ok {
		return v
	}
	return ""
}

// RequestIDFromContext extracts the request ID from context.
// Returns empty string if not present.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(RequestIDKey).(string); ok {
		return v
	}
	return ""
}

// UserIDFromContext extracts the user ID from context.
// Returns empty string if not present.
func UserIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(UserIDKey).(string); ok {
		return v
	}
	return ""
}

// WithSessionID returns a new context with the session ID set.
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, SessionIDKey, sessionID)
}

// WithRequestID returns a new context with the request ID set.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// WithUserID returns a new context with the user ID set.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}
