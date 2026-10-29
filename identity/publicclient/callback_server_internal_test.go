package publicclient

import (
	"net/http"
	"testing"
)

// TestCallbackServerTimeouts expects the loopback callback server to bound
// header, read, write and idle time.
func TestCallbackServerTimeouts(t *testing.T) {
	srv := newCallbackServer(http.NotFoundHandler())
	if srv.ReadHeaderTimeout <= 0 || srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Errorf("timeouts header=%v read=%v write=%v idle=%v, want all set",
			srv.ReadHeaderTimeout, srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}
