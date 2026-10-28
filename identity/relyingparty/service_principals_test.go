package relyingparty

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// A service account never signs in, so its first request creates its local
// principal when ServicePrincipals is set; later requests find it.
func TestBearerServicePrincipals(t *testing.T) {
	fake := newFakeSystemAuth(t)
	client := fake.client(t)
	serviceToken := func(sub string, typ any) string {
		c := fake.accessClaims(testClientID)
		c["sub"] = sub
		c["name"] = "ci-publisher"
		if typ != nil {
			c[PrincipalTypeClaim] = typ
		}
		return fake.sign(c)
	}
	call := func(cfg BearerConfig, token string) (int, *AuthenticatedPrincipal) {
		var got *AuthenticatedPrincipal
		h := BearerMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, _ = PrincipalFromContext(r.Context()) // nil when absent
		}))
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		withBearer(token)(req)
		h.ServeHTTP(w, req)
		return w.Code, got
	}

	store := NewMemoryPrincipalStore()
	cfg := BearerConfig{Tokens: client, Principals: store, AllowBearerTokens: true, ServicePrincipals: true}
	sub := uuid.NewString()
	code, p := call(cfg, serviceToken(sub, "service"))
	if code != http.StatusOK || p == nil || p.Type != "service" || p.Subject != sub {
		t.Fatalf("first request: %d %+v", code, p)
	}
	local, err := store.FindBySubject(t.Context(), sub)
	if err != nil || local.Type != "service" || local.Name != "ci-publisher" || local.Email != "" {
		t.Fatalf("created principal: %+v %v", local, err)
	}
	code, again := call(cfg, serviceToken(sub, "service"))
	if code != http.StatusOK || again.ID != p.ID {
		t.Errorf("second request: %d %+v, want %s", code, again, p.ID)
	}

	// Without the option, or without the claim, an unknown subject stays
	// unknown.
	off := cfg
	off.ServicePrincipals = false
	if code, _ := call(off, serviceToken(uuid.NewString(), "service")); code != http.StatusUnauthorized {
		t.Errorf("option off: %d", code)
	}
	for _, typ := range []any{nil, "human", true} {
		if code, _ := call(cfg, serviceToken(uuid.NewString(), typ)); code != http.StatusUnauthorized {
			t.Errorf("principal_type %v: %d", typ, code)
		}
	}

	// An inactive service principal is refused like anyone else.
	if err := store.SetActive(local.ID, false); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(cfg, serviceToken(sub, "service")); code != http.StatusUnauthorized {
		t.Errorf("inactive service: %d", code)
	}
}
