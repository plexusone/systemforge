package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/apikey"
)

// allowOwner is an owner check that lets every owner use its keys.
func allowOwner(context.Context, *apikey.APIKey) error { return nil }

// TestAPIKeyOwnerCheck verifies that a valid key is refused once its owner
// no longer has access, by the required and the optional middleware, and
// that a failing check refuses rather than allows.
func TestAPIKeyOwnerCheck(t *testing.T) {
	svc, _ := createTestService()
	org := uuid.New()
	owner := uuid.New()
	result, err := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name: "Org Key", OwnerID: owner, OrganizationID: &org, Scopes: []string{"read:users"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	removed := map[uuid.UUID]bool{}
	check := func(_ context.Context, key *apikey.APIKey) error {
		if key.OwnerID != owner || key.OrganizationID == nil || *key.OrganizationID != org {
			t.Errorf("check got key %+v", key)
		}
		if removed[key.OwnerID] {
			return fmt.Errorf("owner %s left %s: %w", key.OwnerID, org, ErrAPIKeyOwnerNotAllowed)
		}
		return nil
	}
	var seen *Principal
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = GetPrincipal(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	call := func(mw func(http.Handler) http.Handler) int {
		seen = nil
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+result.Key)
		rec := httptest.NewRecorder()
		mw(ok).ServeHTTP(rec, req)
		return rec.Code
	}

	if code := call(RequireAPIKey(svc, check)); code != http.StatusOK || seen == nil || *seen.OrganizationID != org {
		t.Fatalf("member owner: status %d principal %+v", code, seen)
	}

	removed[owner] = true
	if code := call(RequireAPIKey(svc, check)); code != http.StatusUnauthorized || seen != nil {
		t.Errorf("removed owner: status %d principal %+v, want 401", code, seen)
	}
	if code := call(OptionalAPIKey(svc, check)); code != http.StatusOK || seen != nil {
		t.Errorf("removed owner, optional: status %d principal %+v, want unauthenticated", code, seen)
	}

	failing := func(context.Context, *apikey.APIKey) error { return errors.New("database down") }
	if code := call(RequireAPIKey(svc, failing)); code != http.StatusUnauthorized || seen != nil {
		t.Errorf("failing check: status %d principal %+v, want refused", code, seen)
	}

	for name, f := range map[string]func(){
		"no owner check":           func() { APIKeyMiddleware(APIKeyMiddlewareConfig{Service: svc}) },
		"optional, no owner check": func() { OptionalAPIKey(svc, nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}
