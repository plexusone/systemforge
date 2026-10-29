package signupapi

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/signupgate"
)

// TestInternalErrorsDoNotLeak expects a database failure to be logged and
// kept out of the response, including the per-address failures of a
// waitlist invitation.
func TestInternalErrorsDoNotLeak(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	admin := uuid.New()
	var logs bytes.Buffer
	h, err := New(Options{
		Invites: signupgate.NewStore(client), Codes: signupgate.NewCodeStore(client, signupgate.MemberOptions{}),
		Waitlist:  signupgate.NewWaitlist(client),
		Principal: func(*http.Request) (uuid.UUID, error) { return admin, nil },
		IsAdmin:   func(context.Context, uuid.UUID) (bool, error) { return true, nil },
		SignupURL: "https://auth.example.com/signup",
		Logger:    slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// A closed client fails every query with the driver's own text.
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/admin/waitlist/invite", `{"emails":["wait@example.com"]}`},
		{"GET", "/admin/codes", ""},
		{"POST", "/admin/invites", `{"emails":["new@example.com"]}`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		if tc.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		body := rec.Body.String()
		if strings.Contains(body, "closed") || strings.Contains(body, "sql") {
			t.Errorf("%s %s = %d, response leaks the internal error: %s", tc.method, tc.path, rec.Code, body)
		}
		if !strings.Contains(body, "internal error") {
			t.Errorf("%s %s = %d %s, want a generic internal error", tc.method, tc.path, rec.Code, body)
		}
	}
	if !strings.Contains(logs.String(), "closed") {
		t.Errorf("internal error not logged: %s", logs.String())
	}
}
