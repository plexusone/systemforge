package productgraph

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestTrackerMiddleware(t *testing.T) {
	pgServer, delivered := captureServer(t)

	client, err := New(Config{
		ProjectID:     "test-project",
		Endpoint:      pgServer.URL,
		BatchSize:     1,
		BatchInterval: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	handler := RequestTrackerMiddleware(client)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, err := w.Write([]byte("OK"))
		require.NoError(t, err)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)

	lastPayload := next(t, delivered).payload
	require.Len(t, lastPayload.Events, 1)
	event := lastPayload.Events[0]
	assert.Equal(t, EventTypeAPIResponse, event.EventType)
	assert.Equal(t, "POST", event.APIMethod)
	assert.Equal(t, "/api/users", event.APIPath)
	assert.Equal(t, 201, event.APIStatusCode)
	assert.GreaterOrEqual(t, event.APIDurationMs, 0)
}

func TestRequestTrackerMiddleware_WithCorrelation(t *testing.T) {
	pgServer, delivered := captureServer(t)

	client, err := New(Config{
		ProjectID:     "test-project",
		Endpoint:      pgServer.URL,
		BatchSize:     1,
		BatchInterval: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	// Chain correlation and request tracker
	handler := ChainMiddleware(client)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/profile", nil)
	req.Header.Set(HeaderSessionID, "sess-frontend-123")
	req.Header.Set(HeaderUserID, "user-456")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	lastPayload := next(t, delivered).payload
	require.Len(t, lastPayload.Events, 1)
	event := lastPayload.Events[0]
	assert.Equal(t, "sess-frontend-123", event.SessionID)
	assert.Equal(t, "user-456", event.UserID)
}

func TestRequestTrackerMiddleware_NilClient(t *testing.T) {
	handler := RequestTrackerMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	// Should not panic
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestResponseWriter(t *testing.T) {
	t.Run("captures status code", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &responseWriter{ResponseWriter: rec, status: http.StatusOK}

		w.WriteHeader(http.StatusNotFound)
		assert.Equal(t, http.StatusNotFound, w.status)
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("default status on write", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &responseWriter{ResponseWriter: rec, status: http.StatusOK}

		_, err := w.Write([]byte("hello"))
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, w.status)
		assert.True(t, w.wroteHeader)
	})

	t.Run("ignores duplicate WriteHeader", func(t *testing.T) {
		rec := httptest.NewRecorder()
		w := &responseWriter{ResponseWriter: rec, status: http.StatusOK}

		w.WriteHeader(http.StatusCreated)
		w.WriteHeader(http.StatusNotFound) // Should be ignored

		assert.Equal(t, http.StatusCreated, w.status)
	})
}
