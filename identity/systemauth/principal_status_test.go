package systemauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		dpopAuth(t, at)(req)
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
	active, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier("b@example.com").SetDisplayName("B").Save(ctx)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	for subject, want := range map[string]bool{
		p.ID.String():      false,
		active.ID.String(): true,
		uuid.NewString():   false, // no principal row: deleted, or never one
		"external|abc":     false, // not a principal ID
		"":                 true,  // a client's own token
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
	live := &HumanPrincipal{Email: "n@example.com", Active: true}
	if err := mem.CreateHuman(ctx, live); err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	for subject, want := range map[string]bool{
		h.ID.String():    false,
		live.ID.String(): true,
		uuid.NewString(): false,
		"external|abc":   false,
		"":               true,
	} {
		if got, err := mem.PrincipalActive(ctx, subject); err != nil || got != want {
			t.Errorf("memory PrincipalActive(%q) = %v, %v; want %v", subject, got, err, want)
		}
	}
}

// TestDeletedPrincipalLosesTokens verifies that hard-deleting a principal
// stops its tokens as deactivating it does: they no longer authenticate or
// refresh, and their family is revoked.
func TestDeletedPrincipalLosesTokens(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStorage()
	s := newRefreshTestServer(t, WithStorage(st))
	subject := newPrincipal(t, s)

	tokens := exchangeCode(t, s, authorizeCode(t, s, "openid offline_access", headerUser(subject)))
	at, _ := tokens["access_token"].(string)
	rt, _ := tokens["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("tokens = %v", tokens)
	}
	if _, err := s.introspect(ctx, at, fosite.AccessToken, s.Session("")); err != nil {
		t.Fatalf("introspection of a live principal's token: %v", err)
	}

	if err := st.DeleteHuman(ctx, uuid.MustParse(subject)); err != nil {
		t.Fatalf("DeleteHuman: %v", err)
	}
	if _, err := s.introspect(ctx, at, fosite.AccessToken, s.Session("")); err == nil {
		t.Error("introspection of a deleted principal's token succeeded")
	}
	if status, body := refresh(t, s, rt); status == http.StatusOK || body["error"] != "invalid_grant" {
		t.Errorf("refresh for a deleted principal: %d %v", status, body)
	}
	// The family was revoked, not merely refused.
	if introspectActive(t, s, at) {
		t.Error("the deleted principal's access token is still stored as active")
	}
}

// TestNonPrincipalSubjectRefused verifies that a session provider naming a
// subject that is not a principal ID gets no tokens.
func TestNonPrincipalSubjectRefused(t *testing.T) {
	s := newRefreshTestServer(t)
	for _, subject := range []string{"external|abc", uuid.NewString()} {
		code := authorizeCode(t, s, "openid", headerUser(subject))
		status, body := tokenRequest(t, s, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {testRPCB},
			"code_verifier": {testVerifier},
		})
		if status == http.StatusOK || body["error"] != "invalid_grant" {
			t.Errorf("subject %q: %d %v", subject, status, body)
		}
	}
}
