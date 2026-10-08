package productgraph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := Config{
			ProjectID: "test-project",
			Endpoint:  "http://localhost:8080/v1/events",
		}
		client, err := New(cfg)
		require.NoError(t, err)
		require.NotNil(t, client)
		t.Cleanup(func() { require.NoError(t, client.Close()) })

		assert.True(t, client.IsEnabled())
		assert.Equal(t, "test-project", client.Config().ProjectID)
	})

	t.Run("missing project ID", func(t *testing.T) {
		cfg := Config{
			Endpoint: "http://localhost:8080/v1/events",
		}
		_, err := New(cfg)
		assert.ErrorIs(t, err, ErrMissingProjectID)
	})

	t.Run("missing endpoint", func(t *testing.T) {
		cfg := Config{
			ProjectID: "test-project",
		}
		_, err := New(cfg)
		assert.ErrorIs(t, err, ErrMissingEndpoint)
	})
}

func TestClient_Track(t *testing.T) {
	var received atomic.Int32
	var lastPayload Payload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		err := json.NewDecoder(r.Body).Decode(&lastPayload)
		require.NoError(t, err)

		//nolint:gosec // G115: Test code with small event counts, no overflow possible
		received.Add(int32(len(lastPayload.Events)))

		w.WriteHeader(http.StatusAccepted)
		err = json.NewEncoder(w).Encode(Response{
			Accepted: len(lastPayload.Events),
			Rejected: 0,
		})
		require.NoError(t, err)
	}))
	defer server.Close()

	client, err := New(Config{
		ProjectID:     "test-project",
		Endpoint:      server.URL,
		BatchSize:     2,
		BatchInterval: 100 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	// Track events
	ctx := context.Background()
	err = client.Track(ctx, NewEvent(EventTypePageView))
	require.NoError(t, err)

	err = client.Track(ctx, NewEvent(EventTypeUIClick))
	require.NoError(t, err)

	// Wait for batch to be sent (batch size reached)
	time.Sleep(200 * time.Millisecond)

	assert.Equal(t, int32(2), received.Load())
	assert.Len(t, lastPayload.Events, 2)
}

func TestClient_TrackWithContext(t *testing.T) {
	server, delivered := captureServer(t)

	client, err := New(Config{
		ProjectID:     "test-project",
		Endpoint:      server.URL,
		BatchSize:     1,
		BatchInterval: time.Hour, // Rely on batch size
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	// Create context with correlation IDs
	ctx := context.Background()
	ctx = WithSessionID(ctx, "sess-123")
	ctx = WithUserID(ctx, "user-456")

	err = client.Track(ctx, NewEvent(EventTypePageView))
	require.NoError(t, err)

	lastPayload := next(t, delivered).payload
	require.Len(t, lastPayload.Events, 1)
	assert.Equal(t, "sess-123", lastPayload.Events[0].SessionID)
	assert.Equal(t, "user-456", lastPayload.Events[0].UserID)
}

func TestClient_TrackAPICall(t *testing.T) {
	server, delivered := captureServer(t)

	client, err := New(Config{
		ProjectID:     "test-project",
		Endpoint:      server.URL,
		BatchSize:     1,
		BatchInterval: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	ctx := WithSessionID(context.Background(), "sess-abc")
	err = client.TrackAPICall(ctx, "POST", "/api/checkout", 200, 150*time.Millisecond)
	require.NoError(t, err)

	lastPayload := next(t, delivered).payload
	require.Len(t, lastPayload.Events, 1)
	event := lastPayload.Events[0]
	assert.Equal(t, EventTypeAPIResponse, event.EventType)
	assert.Equal(t, "POST", event.APIMethod)
	assert.Equal(t, "/api/checkout", event.APIPath)
	assert.Equal(t, 200, event.APIStatusCode)
	assert.Equal(t, 150, event.APIDurationMs)
	assert.Equal(t, "sess-abc", event.SessionID)
}

func TestClient_TrackJourneyStep(t *testing.T) {
	server, delivered := captureServer(t)

	client, err := New(Config{
		ProjectID:     "test-project",
		Endpoint:      server.URL,
		BatchSize:     1,
		BatchInterval: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	ctx := context.Background()
	err = client.TrackJourneyStep(ctx, "checkout_flow", "payment", "Enter Payment Details")
	require.NoError(t, err)

	lastPayload := next(t, delivered).payload
	require.Len(t, lastPayload.Events, 1)
	event := lastPayload.Events[0]
	assert.Equal(t, EventTypeJourneyStep, event.EventType)
	assert.Equal(t, "checkout_flow", event.JourneyID)
	assert.Equal(t, "payment", event.JourneyStep)
	assert.Equal(t, "Enter Payment Details", event.JourneyName)
}

func TestClient_Flush(t *testing.T) {
	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Payload
		err := json.NewDecoder(r.Body).Decode(&payload)
		require.NoError(t, err)
		//nolint:gosec // G115: Test code with small event counts, no overflow possible
		received.Add(int32(len(payload.Events)))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client, err := New(Config{
		ProjectID:     "test-project",
		Endpoint:      server.URL,
		BatchSize:     100, // Large batch size
		BatchInterval: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	ctx := context.Background()
	require.NoError(t, client.Track(ctx, NewEvent(EventTypePageView)))
	require.NoError(t, client.Track(ctx, NewEvent(EventTypeUIClick)))
	require.NoError(t, client.Track(ctx, NewEvent(EventTypeUISubmit)))

	// Manual flush
	err = client.Flush(ctx)
	require.NoError(t, err)

	assert.Equal(t, int32(3), received.Load())
}

func TestClient_Close(t *testing.T) {
	var received atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Payload
		err := json.NewDecoder(r.Body).Decode(&payload)
		require.NoError(t, err)
		//nolint:gosec // G115: Test code with small event counts, no overflow possible
		received.Add(int32(len(payload.Events)))
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	client, err := New(Config{
		ProjectID:     "test-project",
		Endpoint:      server.URL,
		BatchSize:     100,
		BatchInterval: time.Hour,
	})
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, client.Track(ctx, NewEvent(EventTypePageView)))
	require.NoError(t, client.Track(ctx, NewEvent(EventTypeUIClick)))

	// Close should flush remaining events
	err = client.Close()
	require.NoError(t, err)

	assert.Equal(t, int32(2), received.Load())

	// Track after close should fail
	err = client.Track(ctx, NewEvent(EventTypePageView))
	assert.ErrorIs(t, err, ErrClientClosed)
}

func TestClient_APIKeyHeader(t *testing.T) {
	server, delivered := captureServer(t)

	client, err := New(Config{
		ProjectID:     "test-project",
		Endpoint:      server.URL,
		APIKey:        "pk_test_secret",
		BatchSize:     1,
		BatchInterval: time.Hour,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	err = client.Track(context.Background(), NewEvent(EventTypePageView))
	require.NoError(t, err)
	assert.Equal(t, "pk_test_secret", next(t, delivered).apiKey)
}
