package scimtoken_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/scimtoken"
	"github.com/plexusone/systemforge/identity/scim/store"
)

func newSCIMAPI(t *testing.T, f *fixture) *scim.API {
	t.Helper()
	cfg := scim.DefaultConfig()
	cfg.BaseURL = "/scim/v2"
	provider, err := scim.NewProvider(cfg, store.NewEntStore(f.client, &store.Config{BaseURL: "/scim/v2", DefaultRole: "member"}),
		scim.WithAuthorizationHook(scim.NewScopedAuthorizationHook(true)))
	if err != nil {
		t.Fatal(err)
	}
	api, err := scim.NewAPI(provider)
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func TestCredentialFuncBindsTenant(t *testing.T) {
	f := newFixture(t, openSQLite(t))
	s := f.service()
	ctx := context.Background()
	a, err := s.Issue(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Issue(ctx, f.ownerB, f.orgB, scimtoken.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	api := newSCIMAPI(t, f)

	type result struct {
		code    int
		scope   scim.Scope
		bound   bool
		subject string
	}
	serve := func(fn func(*http.Request) (scim.Credential, error), auth string) result {
		var res result
		h := api.CredentialMiddleware(fn)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			res.scope, res.bound = scim.ScopeFromContext(r.Context())
			res.subject = scim.AuthSubjectFromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/Users", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		res.code = rr.Code
		return res
	}
	tenantOnly := s.CredentialFunc(scimtoken.CredentialOptions{})

	if r := serve(tenantOnly, "Bearer "+a.Token); r.code != http.StatusOK || !r.bound || r.scope.OrganizationID != f.orgA || r.scope.Platform {
		t.Errorf("tenant A: %+v", r)
	} else if r.subject != scimtoken.SubjectPrefix+a.Metadata.ID.String() {
		t.Errorf("tenant A subject %q", r.subject)
	}
	if r := serve(tenantOnly, "bearer "+b.Token); r.code != http.StatusOK || r.scope.OrganizationID != f.orgB {
		t.Errorf("tenant B: %+v", r)
	}
	if r := serve(tenantOnly, ""); r.code != http.StatusUnauthorized {
		t.Errorf("no token: %d", r.code)
	}
	if r := serve(tenantOnly, "Bearer "+strings.Repeat("x", 20)); r.code != http.StatusUnauthorized {
		t.Errorf("foreign token without platform credentials: %d", r.code)
	}
	if err := s.Revoke(ctx, f.ownerA, f.orgA, a.Metadata.ID); err != nil {
		t.Fatal(err)
	}
	if r := serve(tenantOnly, "Bearer "+a.Token); r.code != http.StatusUnauthorized {
		t.Errorf("revoked token: %d", r.code)
	}

	// Platform credentials are separate and explicit.
	platformToken := strings.Repeat("p", 24)
	withPlatform := s.CredentialFunc(scimtoken.CredentialOptions{
		Platform: func(r *http.Request) (scim.Credential, error) {
			if r.Header.Get("Authorization") != "Bearer "+platformToken {
				return scim.Credential{}, errors.New("unknown operator token")
			}
			return scim.Credential{Subject: "ops", Scopes: []string{scim.ScopeFull}, Scope: scim.Scope{Platform: true}}, nil
		},
	})
	if r := serve(withPlatform, "Bearer "+platformToken); r.code != http.StatusOK || !r.scope.Platform {
		t.Errorf("platform credential: %+v", r)
	}
	if r := serve(withPlatform, "Bearer "+strings.Repeat("q", 24)); r.code != http.StatusUnauthorized {
		t.Errorf("unknown platform credential: %d", r.code)
	}
	if r := serve(withPlatform, "Bearer "+b.Token); r.code != http.StatusOK || r.scope.Platform || r.scope.OrganizationID != f.orgB {
		t.Errorf("tenant token with platform configured: %+v", r)
	}
	// A platform function returning a tenant scope is refused.
	misbound := s.CredentialFunc(scimtoken.CredentialOptions{
		Platform: func(*http.Request) (scim.Credential, error) {
			return scim.Credential{Subject: "x", Scope: scim.Scope{OrganizationID: f.orgA}}, nil
		},
	})
	if r := serve(misbound, "Bearer "+platformToken); r.code != http.StatusUnauthorized {
		t.Errorf("platform function with a tenant scope: %d", r.code)
	}
}

// TestTenantTokenProvisionsOnlyItsTenant drives the SCIM API end to end:
// a user created with tenant A's token is a member of A, not visible to B.
func TestTenantTokenProvisionsOnlyItsTenant(t *testing.T) {
	f := newFixture(t, openSQLite(t))
	s := f.service()
	ctx := context.Background()
	a, err := s.Issue(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Issue(ctx, f.ownerB, f.orgB, scimtoken.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	api := newSCIMAPI(t, f)
	h := api.CredentialMiddleware(s.CredentialFunc(scimtoken.CredentialOptions{}))(api)

	do := func(method, path, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			req.Header.Set("Content-Type", "application/scim+json")
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}
	rr := do(http.MethodPost, "/scim/v2/Users", a.Token, `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ada@example.com"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create with A's token: %d %s", rr.Code, rr.Body.String())
	}
	count := func(token string) int {
		t.Helper()
		rr := do(http.MethodGet, "/scim/v2/Users", token, "")
		if rr.Code != http.StatusOK {
			t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
		}
		var body struct {
			TotalResults int `json:"totalResults"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.TotalResults
	}
	if n := count(a.Token); n != 1 {
		t.Errorf("tenant A sees %d users, want 1", n)
	}
	if n := count(b.Token); n != 0 {
		t.Errorf("tenant B sees %d users, want 0", n)
	}
}
