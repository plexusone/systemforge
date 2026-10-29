package multiapp

import "testing"

// TestHTTPServerTimeouts expects the server Run starts to bound header,
// read, write and idle time.
func TestHTTPServerTimeouts(t *testing.T) {
	srv := (&Server{}).httpServer(":0")
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Errorf("timeouts header=%v read=%v write=%v idle=%v, want all set",
			srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}
