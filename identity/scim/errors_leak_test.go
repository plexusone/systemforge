package scim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
)

const dbErrorText = "pq: relation sf_humans does not exist"

// failingStore fails every user read with a raw, non-SCIM error.
type failingStore struct{ *mockStore }

func (failingStore) GetUserByID(context.Context, string) (*User, error) {
	return nil, errors.New(dbErrorText)
}

// Internal error text, from a store, a credential check or anywhere else,
// is logged and never returned to a SCIM client; SCIM errors pass through.
func TestInternalErrorTextIsNotReturned(t *testing.T) {
	ctx := context.Background()
	raw := errors.New(dbErrorText)

	if e := ToSCIMError(raw); e.Status != http.StatusInternalServerError || strings.Contains(e.Detail, "pq:") {
		t.Errorf("ToSCIMError = %+v", e)
	}
	if e := ToSCIMError(fmt.Errorf("wrapped: %w", ErrNotFound("user not found"))); e.Status != http.StatusNotFound {
		t.Errorf("ToSCIMError(wrapped SCIM error) = %+v", e)
	}
	if e := InternalError(ctx, raw); strings.Contains(e.Detail, "pq:") {
		t.Errorf("InternalError detail = %q", e.Detail)
	}
	var he huma.StatusError
	if err := toHumaErrorFromErr(ctx, raw); !errors.As(err, &he) || he.GetStatus() != http.StatusInternalServerError || strings.Contains(err.Error(), "pq:") {
		t.Errorf("toHumaErrorFromErr = %v", err)
	}

	p, err := NewProvider(DefaultConfig(), failingStore{newMockStore()}, WithAuthorizationHook(AllowAllAuthorizationHook{}))
	if err != nil {
		t.Fatal(err)
	}
	api, err := NewAPI(p)
	if err != nil {
		t.Fatal(err)
	}
	h := api.CredentialMiddleware(func(r *http.Request) (Credential, error) {
		if r.Header.Get("Authorization") == "" {
			return Credential{}, errors.New(dbErrorText)
		}
		return Credential{Subject: "ops", Scopes: []string{ScopeFull}, Scope: Scope{Platform: true}}, nil
	})(api)

	for _, tc := range []struct {
		name   string
		auth   string
		status int
	}{
		{"credential check error", "", http.StatusUnauthorized},
		{"store error", "Bearer x", http.StatusInternalServerError},
	} {
		req := httptest.NewRequest(http.MethodGet, DefaultConfig().BaseURL+"/Users/u1", nil)
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tc.status || strings.Contains(rr.Body.String(), "pq:") {
			t.Errorf("%s: %d %s", tc.name, rr.Code, rr.Body.String())
		}
	}
}
