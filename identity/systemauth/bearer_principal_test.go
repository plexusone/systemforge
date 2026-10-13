package systemauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
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
