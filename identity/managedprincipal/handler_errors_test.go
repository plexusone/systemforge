package managedprincipal

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFailDoesNotLeakErrorText expects an unexpected error to be logged
// and answered generically, and a mapped error to send only its sentinel
// text, never what a wrapper adds.
func TestFailDoesNotLeakErrorText(t *testing.T) {
	const internalText = `pq: duplicate key value violates unique constraint "humans_email_key"`
	cases := []struct {
		err    error
		status int
		body   string
	}{
		{errors.New(internalText), http.StatusInternalServerError, "internal error"},
		{fmt.Errorf("%w: %s", ErrEmailInUse, internalText), http.StatusConflict, "email is already in use"},
		{fmt.Errorf("%w: %s", ErrInvalidManager, internalText), http.StatusBadRequest, "manager must be an active human"},
	}
	for _, tc := range cases {
		var logs bytes.Buffer
		h := &handler{svc: &Service{logger: slog.New(slog.NewTextHandler(&logs, nil))}}
		w := httptest.NewRecorder()
		h.fail(w, httptest.NewRequest(http.MethodPost, "/", nil), tc.err)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.body) {
			t.Errorf("%v: %d %s, want %d %q", tc.err, w.Code, w.Body.String(), tc.status, tc.body)
		}
		if strings.Contains(w.Body.String(), "humans_email_key") {
			t.Errorf("%v: response leaks the internal error: %s", tc.err, w.Body.String())
		}
	}
}
