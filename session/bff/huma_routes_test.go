package bff

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)

// Mounted as documented, the BFF handler must serve /bff/logout, /bff/session
// and /bff/refresh: RegisterHumaRoutes only documents them. Stub handlers
// registered on the shared router used to answer instead, so logout did not
// end the session.
func TestRegisterHumaRoutesDoesNotShadowTheHandler(t *testing.T) {
	router := chi.NewRouter()
	api := humachi.New(router, huma.DefaultConfig("test", "1.0.0"))
	router.Mount("/bff", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot) // stands in for the real BFF handler
	}))
	RegisterHumaRoutes(api, HumaConfig{PathPrefix: "/bff"})

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/bff/logout"},
		{http.MethodGet, "/bff/session"},
		{http.MethodPost, "/bff/refresh"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Origin", "https://app.example.com")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusTeapot {
			t.Errorf("%s %s: status %d, want the mounted BFF handler (418)", tc.method, tc.path, rr.Code)
		}
	}

	paths := api.OpenAPI().Paths
	if paths["/bff/logout"] == nil || paths["/bff/logout"].Post == nil ||
		paths["/bff/session"] == nil || paths["/bff/session"].Get == nil ||
		paths["/bff/refresh"] == nil || paths["/bff/refresh"].Post == nil {
		t.Fatalf("BFF operations missing from the OpenAPI spec: %v", paths)
	}
	if op := paths["/bff/logout"].Post; op.Responses["200"] == nil || op.Responses["200"].Content["application/json"].Schema == nil {
		t.Errorf("logout response schema not documented: %+v", op.Responses)
	}
}
