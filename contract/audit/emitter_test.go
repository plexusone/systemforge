package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

func TestLogEmitter(t *testing.T) {
	var buf bytes.Buffer
	e := NewLogEmitter(slog.New(slog.NewJSONHandler(&buf, nil)))
	actor := uuid.New()
	ev := &Event{
		EventType: "systemauth.sign_in",
		Action:    "sign_in",
		Actor:     Actor{ID: actor, Type: "principal"},
		Resource:  Resource{Type: "login_session"},
		Context:   Context{RequestID: "req-1", ClientIP: "203.0.113.1", SessionID: "session-token-must-not-be-logged"},
		Outcome:   OutcomeFailure,
		Details:   map[string]any{"reason": "invalid_state"},
	}
	if err := e.Emit(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log record %q: %v", buf.String(), err)
	}
	if rec["msg"] != "security event" || rec["level"] != "WARN" || rec["event_type"] != "systemauth.sign_in" || rec["outcome"] != OutcomeFailure {
		t.Errorf("record: %v", rec)
	}
	ctxAttrs, ok := rec["context"].(map[string]any)
	if !ok || ctxAttrs["request_id"] != "req-1" || ctxAttrs["client_ip"] != "203.0.113.1" {
		t.Errorf("context: %v", rec["context"])
	}
	if bytes.Contains(buf.Bytes(), []byte("session-token-must-not-be-logged")) {
		t.Error("session ID logged")
	}
	actorAttrs, ok := rec["actor"].(map[string]any)
	if !ok || actorAttrs["id"] != actor.String() {
		t.Errorf("actor: %v", rec["actor"])
	}
	if d, ok := rec["details"].(map[string]any); !ok || d["reason"] != "invalid_state" {
		t.Errorf("details: %v", rec["details"])
	}
}

func TestNopEmitterAndRequestID(t *testing.T) {
	if err := (NopEmitter{}).Emit(context.Background(), &Event{}); err != nil {
		t.Fatal(err)
	}
	if got := RequestID(context.Background()); got != "" {
		t.Errorf("RequestID outside a request = %q", got)
	}
	var got string
	h := middleware.RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = RequestID(r.Context()) }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if got == "" {
		t.Error("RequestID inside a request is empty")
	}
}
