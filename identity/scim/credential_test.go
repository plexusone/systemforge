package scim

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestCredentialMiddlewareBindsScope(t *testing.T) {
	provider, _, err := setupTestProvider()
	if err != nil {
		t.Fatal(err)
	}
	api, err := NewAPI(provider)
	if err != nil {
		t.Fatal(err)
	}
	org := uuid.New()

	run := func(cred Credential, authErr error) (int, Scope, bool) {
		var got Scope
		var ok bool
		h := api.CredentialMiddleware(func(*http.Request) (Credential, error) { return cred, authErr })(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, ok = ScopeFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/Users", nil))
		return rr.Code, got, ok
	}

	if code, got, ok := run(Credential{Subject: "idp", Scope: Scope{OrganizationID: org}}, nil); code != http.StatusOK || !ok || got.OrganizationID != org {
		t.Errorf("tenant credential: %d %+v %v", code, got, ok)
	}
	if code, got, ok := run(Credential{Subject: "ops", Scope: Scope{Platform: true}}, nil); code != http.StatusOK || !ok || !got.Platform {
		t.Errorf("platform credential: %d %+v %v", code, got, ok)
	}
	if code, _, _ := run(Credential{Subject: "unbound"}, nil); code != http.StatusForbidden {
		t.Errorf("unbound credential: status %d, want 403", code)
	}
	if code, _, _ := run(Credential{Scope: Scope{OrganizationID: org, Platform: true}}, nil); code != http.StatusForbidden {
		t.Errorf("credential with both scopes: status %d, want 403", code)
	}
	if code, _, _ := run(Credential{}, errors.New("bad token")); code != http.StatusUnauthorized {
		t.Errorf("failed authentication: status %d, want 401", code)
	}
}
