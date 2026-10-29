package connections

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cf "github.com/plexusone/connectforge"
)

// TestFailDoesNotLeakInternalErrors expects provider, network and storage
// error text to be logged, never written to the response.
func TestFailDoesNotLeakInternalErrors(t *testing.T) {
	const internalText = "dial tcp 10.0.0.5:5432: connection refused"
	cases := []struct {
		err    error
		status int
	}{
		{fmt.Errorf("%w: fakecdn: %w", cf.ErrTransient, errors.New(internalText)), http.StatusBadGateway},
		{fmt.Errorf("%w: %s", cf.ErrRateLimited, internalText), http.StatusBadGateway},
		{fmt.Errorf("%w: %s", cf.ErrInvalidCredential, internalText), http.StatusUnprocessableEntity},
		{fmt.Errorf("%w: %s", cf.ErrInsufficientScope, internalText), http.StatusUnprocessableEntity},
		{fmt.Errorf("%w: %s", cf.ErrConflict, internalText), http.StatusConflict},
		{errors.New(internalText), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		var logs bytes.Buffer
		h := &api{log: slog.New(slog.NewTextHandler(&logs, nil))}
		w := httptest.NewRecorder()
		h.fail(call{w: w, r: httptest.NewRequest(http.MethodPost, "/", nil)}, tc.err)
		if w.Code != tc.status {
			t.Errorf("%v: status = %d, want %d", tc.err, w.Code, tc.status)
		}
		if strings.Contains(w.Body.String(), "10.0.0.5") {
			t.Errorf("%v: response %q leaks the internal error", tc.err, w.Body.String())
		}
		if !strings.Contains(logs.String(), "10.0.0.5") && tc.status != http.StatusConflict {
			t.Errorf("%v: error not logged", tc.err)
		}
	}
}
