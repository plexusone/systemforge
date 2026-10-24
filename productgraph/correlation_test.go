package productgraph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCorrelationMiddleware(t *testing.T) {
	t.Run("extracts session ID", func(t *testing.T) {
		var capturedSessionID string

		handler := CorrelationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedSessionID = SessionIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(HeaderSessionID, "sess-123")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, "sess-123", capturedSessionID)
	})

	t.Run("extracts request ID", func(t *testing.T) {
		var capturedRequestID string

		handler := CorrelationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedRequestID = RequestIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(HeaderRequestID, "req-456")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, "req-456", capturedRequestID)
		assert.Equal(t, "req-456", rec.Header().Get(HeaderRequestID))
	})

	t.Run("generates request ID if not provided", func(t *testing.T) {
		var capturedRequestID string

		handler := CorrelationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedRequestID = RequestIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.NotEmpty(t, capturedRequestID)
		assert.Equal(t, capturedRequestID, rec.Header().Get(HeaderRequestID))
	})

	t.Run("ignores client-supplied user ID", func(t *testing.T) {
		var capturedUserID string

		handler := CorrelationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedUserID = UserIDFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(HeaderUserID, "user-789")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Empty(t, capturedUserID)
	})

	t.Run("returns empty for missing values", func(t *testing.T) {
		ctx := context.Background()

		assert.Empty(t, SessionIDFromContext(ctx))
		assert.Empty(t, RequestIDFromContext(ctx))
		assert.Empty(t, UserIDFromContext(ctx))
	})
}

func TestContextHelpers(t *testing.T) {
	ctx := context.Background()

	ctx = WithSessionID(ctx, "sess-abc")
	ctx = WithRequestID(ctx, "req-def")
	ctx = WithUserID(ctx, "user-ghi")

	assert.Equal(t, "sess-abc", SessionIDFromContext(ctx))
	assert.Equal(t, "req-def", RequestIDFromContext(ctx))
	assert.Equal(t, "user-ghi", UserIDFromContext(ctx))
}
