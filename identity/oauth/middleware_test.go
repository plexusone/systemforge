package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plexusone/systemforge/identity/ent/oauthapp"
	"github.com/plexusone/systemforge/identity/ent/principal"
)

// TestMiddlewareChecksClientAndPrincipal verifies that Middleware refuses
// a valid access token issued to a client it does not accept, issued to a
// client that was deactivated, or held by a principal that was
// deactivated, and that it cannot be used without choosing which clients
// to accept.
func TestMiddlewareChecksClientAndPrincipal(t *testing.T) {
	ctx := context.Background()
	f := newFlow(t)
	user, err := f.db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier("ada@example.com").SetDisplayName("Ada").Save(ctx)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	verifier, challenge := pkcePair()
	resp, err := f.token(codeExchange(f.authorizeAs(user.ID.String(), challenge), verifier, flowRedirect))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	token := resp.GetAccessToken()

	call := func(opts ...Option) int {
		t.Helper()
		api, err := NewAPI(f.p, opts...)
		if err != nil {
			t.Fatalf("NewAPI: %v", err)
		}
		h := api.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := call(WithAcceptedClientIDs(f.clientID)); code != http.StatusOK {
		t.Fatalf("accepted client: status %d", code)
	}
	if code := call(WithAnyClient()); code != http.StatusOK {
		t.Fatalf("any client: status %d", code)
	}
	if code := call(WithAcceptedClientIDs("another-client")); code != http.StatusUnauthorized {
		t.Errorf("token of a client not accepted: status %d, want 401", code)
	}

	func() {
		defer func() {
			if recover() == nil {
				t.Error("Middleware without an accepted-client choice did not panic")
			}
		}()
		call()
	}()

	if _, err := f.db.Principal.UpdateOneID(user.ID).SetActive(false).Save(ctx); err != nil {
		t.Fatalf("deactivate principal: %v", err)
	}
	if code := call(WithAnyClient()); code != http.StatusUnauthorized {
		t.Errorf("deactivated principal: status %d, want 401", code)
	}
	if _, err := f.db.Principal.UpdateOneID(user.ID).SetActive(true).Save(ctx); err != nil {
		t.Fatalf("reactivate principal: %v", err)
	}

	if _, err := f.db.OAuthApp.Update().Where(oauthapp.ClientIDEQ(f.clientID)).SetActive(false).Save(ctx); err != nil {
		t.Fatalf("deactivate app: %v", err)
	}
	if code := call(WithAnyClient()); code != http.StatusUnauthorized {
		t.Errorf("deactivated client: status %d, want 401", code)
	}
}
