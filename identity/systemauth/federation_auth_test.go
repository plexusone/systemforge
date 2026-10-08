package systemauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func newFederationServer(t *testing.T, store Storage, opts ...FederationOption) *Server {
	t.Helper()
	s, err := NewEmbedded(Config{Issuer: testIssuer}, WithStorage(store))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	NewFederationEndpoints(s, NewDefaultIdentitySyncHandler(store), opts...).RegisterRoutes()
	return s
}

func syncRequest(t *testing.T, s *Server, bearer, email string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(IdentitySyncRequest{Action: "create", Identity: &GlobalIdentity{ID: uuid.New(), Email: email, DisplayName: "Eve"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/systemforge/identity/sync", bytes.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w
}

// TestFederationSyncNeedsAnAuthenticator verifies that the identity sync
// endpoint, which treats its body as truth, is unreachable unauthenticated.
func TestFederationSyncNeedsAnAuthenticator(t *testing.T) {
	ctx := context.Background()

	// With no authenticator the endpoint is not registered at all.
	store := NewMemoryStorage()
	s := newFederationServer(t, store)
	if w := syncRequest(t, s, "", "victim@example.com"); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Errorf("sync with no authenticator configured: %d, want the route absent", w.Code)
	}
	lookup := httptest.NewRecorder()
	s.ServeHTTP(lookup, httptest.NewRequest(http.MethodGet, "/systemforge/identity/lookup/"+uuid.NewString(), nil))
	if lookup.Code != http.StatusNotFound && lookup.Code != http.StatusMethodNotAllowed {
		t.Errorf("lookup with no authenticator configured: %d", lookup.Code)
	}
	health := httptest.NewRecorder()
	s.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/systemforge/health", nil))
	if health.Code != http.StatusOK {
		t.Errorf("health: %d", health.Code)
	}

	// With a shared secret, only the holder may sync.
	victim := &HumanPrincipal{Email: "victim@example.com", DisplayName: "Victim", Active: true}
	store = NewMemoryStorage()
	if err := store.CreateHuman(ctx, victim); err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	s = newFederationServer(t, store, WithFederationAuthenticator(SharedSecretAuthenticator("correct-horse-battery-staple")))
	for name, bearer := range map[string]string{"no token": "", "wrong token": "guess", "prefix of the secret": "correct-horse"} {
		if w := syncRequest(t, s, bearer, "victim@example.com"); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", name, w.Code)
		}
	}
	if links, err := store.GetHumanByEmail(ctx, "victim@example.com"); err != nil || links.ID != victim.ID {
		t.Fatalf("victim after refused requests: %+v, %v", links, err)
	}
	if w := syncRequest(t, s, "correct-horse-battery-staple", "new@example.com"); w.Code != http.StatusOK {
		t.Errorf("sync with the secret: %d %s", w.Code, w.Body)
	}
	if _, err := store.GetHumanByEmail(ctx, "new@example.com"); err != nil {
		t.Errorf("authorized sync did not create the human: %v", err)
	}

	// An empty configured secret admits nothing, not everything.
	s = newFederationServer(t, NewMemoryStorage(), WithFederationAuthenticator(SharedSecretAuthenticator("")))
	if w := syncRequest(t, s, "", "x@example.com"); w.Code != http.StatusUnauthorized {
		t.Errorf("empty secret: %d, want 401", w.Code)
	}
}

func TestFederationLookupReadsThePathParameter(t *testing.T) {
	s := newFederationServer(t, NewMemoryStorage(), WithFederationAuthenticator(SharedSecretAuthenticator("s3cret-s3cret-s3cret")))
	id := uuid.New()
	req := httptest.NewRequest(http.MethodGet, "/systemforge/identity/lookup/"+id.String(), nil)
	req.Header.Set("Authorization", "Bearer s3cret-s3cret-s3cret")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != http.StatusOK || out["global_identity_id"] != id.String() {
		t.Errorf("lookup: %d %s", w.Code, w.Body)
	}
	unauth := httptest.NewRecorder()
	s.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/systemforge/identity/lookup/"+id.String(), nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated lookup: %d", unauth.Code)
	}
}
