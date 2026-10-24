package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A disabled instance must accept every recording call.
func TestDisabledObservabilityRecords(t *testing.T) {
	o, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	o.RecordAuthRequest(ctx, "authorization_code", "client", "ok")
	o.RecordAuthLatency(ctx, "authorization_code", "/token", 1)
	o.RecordTokenIssued(ctx, "authorization_code", "client")
	o.RecordTokenValidation(ctx, ResultValid)
	o.RecordSessionsActive(ctx, 1)
	o.RecordJWTValidation(ctx, ResultValid)
	o.RecordJWTLatency(ctx, 1)
	o.RecordAPIKeyValidation(ctx, ResultValid)

	h := o.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status %d, want 204", rr.Code)
	}
}
