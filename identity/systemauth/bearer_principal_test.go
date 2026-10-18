package systemauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/requestprincipal"
)

func TestBearerPrincipal(t *testing.T) {
	f := newOrgsFixture(t)
	tok := f.tokens(t, "openid profile")["access_token"].(string) //nolint:forcetypeassert // the token endpoint returns a string
	req := func(authz string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/providers", nil)
		if authz != "" {
			r.Header.Set("Authorization", authz)
		}
		return r
	}

	id, err := f.s.BearerPrincipal(req("Bearer "+tok), "profile")
	if err != nil || id != f.principal {
		t.Fatalf("valid token: %s, %v", id, err)
	}
	if _, err := f.s.BearerPrincipal(req("Bearer "+tok), "systemforge:connections:write"); !errors.Is(err, ErrBearerScope) {
		t.Fatalf("missing scope: %v", err)
	}
	if _, err := f.s.BearerPrincipal(req("Bearer not-a-token"), "profile"); !errors.Is(err, ErrBearerInvalid) {
		t.Fatalf("invalid token: %v", err)
	}
	if _, err := f.s.BearerPrincipal(req(""), "profile"); !errors.Is(err, ErrBearerMissing) {
		t.Fatalf("no token: %v", err)
	}

	for err, want := range map[error]int{
		ErrBearerMissing: http.StatusUnauthorized,
		ErrBearerInvalid: http.StatusUnauthorized,
		ErrBearerScope:   http.StatusForbidden,
	} {
		w := httptest.NewRecorder()
		WriteBearerError(w, err, "s:r:v")
		if w.Code != want || w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%v: %d %q", err, w.Code, w.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestBearerAccessCarriesTheClient(t *testing.T) {
	f := newOrgsFixture(t)
	tok := f.tokens(t, "openid profile")["access_token"].(string) //nolint:forcetypeassert // the token endpoint returns a string
	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	r.Header.Set("Authorization", "Bearer "+tok)

	g, err := f.s.BearerAccess(r, "profile")
	if err != nil {
		t.Fatal(err)
	}
	if g.PrincipalID != f.principal || g.ClientID != "spa" || g.TokenID == "" || g.ExpiresAt.IsZero() {
		t.Fatalf("grant %+v", g)
	}
}

func TestBearerAuthenticator(t *testing.T) {
	f := newOrgsFixture(t)
	tok := f.tokens(t, "openid profile")["access_token"].(string) //nolint:forcetypeassert // the token endpoint returns a string
	served := false
	h := requestprincipal.Middleware(requestprincipal.Options{}, f.s.BearerAuthenticator("profile"))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := requestprincipal.FromContext(r.Context())
			if !ok || p.PrincipalID != f.principal.String() || p.Claims["client_id"] != "spa" ||
				p.Protocol != requestprincipal.ProtocolOIDC || p.Proof.Issuer != testIssuer {
				t.Errorf("principal %+v", p)
			}
			served = true
			w.WriteHeader(http.StatusNoContent)
		}))
	call := func(authz string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		if authz != "" {
			r.Header.Set("Authorization", authz)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := call("Bearer " + tok); w.Code != http.StatusNoContent || !served {
		t.Fatalf("valid token: %d", w.Code)
	}
	for name, tc := range map[string]struct {
		authz string
		want  int
	}{
		"no token":      {"", http.StatusUnauthorized},
		"unknown token": {"Bearer not-a-token", http.StatusUnauthorized},
	} {
		if w := call(tc.authz); w.Code != tc.want || w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: %d %q", name, w.Code, w.Header().Get("WWW-Authenticate"))
		}
	}

	scoped := requestprincipal.Middleware(requestprincipal.Options{}, f.s.BearerAuthenticator("systemforge:other"))(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	scoped.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Fatalf("missing scope: %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
}
