package systemauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
)

// TestDeactivatedPrincipalLosesTokens verifies that deactivating a
// principal outside SystemAuth (as SCIM or federation sync would) stops
// its existing tokens at once: they no longer authenticate or refresh, and
// their family is revoked for good.
func TestDeactivatedPrincipalLosesTokens(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	s := newRefreshTestServer(t, WithStorage(NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))))
	p, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier("kim@example.com").SetDisplayName("Kim").Save(ctx)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}

	tokens := exchangeCode(t, s, authorizeCode(t, s, "openid offline_access", headerUser(p.ID.String())))
	at, _ := tokens["access_token"].(string)
	rt, _ := tokens["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("tokens = %v", tokens)
	}

	protected := s.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	call := func() int {
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		req.Header.Set("Authorization", "Bearer "+at)
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, req)
		return w.Code
	}
	if code := call(); code != http.StatusNoContent {
		t.Fatalf("active principal: %d", code)
	}

	if err := db.Principal.UpdateOneID(p.ID).SetActive(false).Exec(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if code := call(); code != http.StatusUnauthorized {
		t.Errorf("Middleware with a deactivated principal: %d", code)
	}
	if _, err := s.introspect(ctx, at, fosite.AccessToken, s.Session("")); err == nil {
		t.Error("introspection of a deactivated principal's token succeeded")
	}
	if status, body := refresh(t, s, rt); status == http.StatusOK || body["error"] != "invalid_grant" {
		t.Errorf("refresh for a deactivated principal: %d %v", status, body)
	}

	// The family stays revoked after reactivation.
	if err := db.Principal.UpdateOneID(p.ID).SetActive(true).Exec(ctx); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if status, _ := refresh(t, s, rt); status == http.StatusOK {
		t.Error("refresh token works again after reactivation")
	}
	if code := call(); code != http.StatusUnauthorized {
		t.Errorf("access token works again after reactivation: %d", code)
	}

	// A new sign-in works once the principal is active.
	fresh := exchangeCode(t, s, authorizeCode(t, s, "openid offline_access", headerUser(p.ID.String())))
	if fresh["access_token"] == nil {
		t.Errorf("new sign-in after reactivation: %v", fresh)
	}
}

func TestPrincipalActive(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	s := NewEntStorage(db)
	p, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier("a@example.com").SetDisplayName("A").SetActive(false).Save(ctx)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	for subject, want := range map[string]bool{
		p.ID.String():    false,
		uuid.NewString(): true, // not a principal SystemAuth holds
		"external|abc":   true,
	} {
		if got, err := s.PrincipalActive(ctx, subject); err != nil || got != want {
			t.Errorf("PrincipalActive(%q) = %v, %v; want %v", subject, got, err, want)
		}
	}

	mem := NewMemoryStorage()
	h := &HumanPrincipal{Email: "m@example.com", Active: false}
	if err := mem.CreateHuman(ctx, h); err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if got, err := mem.PrincipalActive(ctx, h.ID.String()); err != nil || got {
		t.Errorf("memory inactive human = %v, %v", got, err)
	}
}
