package productgraph

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// capture is one request the fake event endpoint received.
type capture struct {
	payload Payload
	apiKey  string
}

// captureServer is a fake event endpoint that hands each request to the
// test through a channel, so tests wait for delivery instead of sleeping
// and never share variables with the handler goroutine.
func captureServer(t *testing.T) (*httptest.Server, <-chan capture) {
	t.Helper()
	ch := make(chan capture, 16)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c capture
		if err := json.NewDecoder(r.Body).Decode(&c.payload); err != nil {
			t.Errorf("decoding payload: %v", err) // not FailNow: this is not the test goroutine
		}
		c.apiKey = r.Header.Get("X-PG-API-Key")
		w.WriteHeader(http.StatusAccepted)
		ch <- c
	}))
	t.Cleanup(server.Close)
	return server, ch
}

// next waits for the next request to the fake endpoint.
func next(t *testing.T, ch <-chan capture) capture {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no events delivered")
		return capture{}
	}
}
