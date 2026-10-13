package systemauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plexusone/systemforge/identity/appcatalog"
)

func TestAppCatalogIsPublished(t *testing.T) {
	c, err := appcatalog.New(appcatalog.App{ID: "build", Name: "Build", URL: "https://app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewEmbedded(Config{Issuer: testIssuer}, WithAppCatalog(c))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, appcatalog.WellKnownPath, nil))
	var doc appcatalog.Document
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || w.Code != http.StatusOK {
		t.Fatalf("catalog: %d %s (%v)", w.Code, w.Body, err)
	}
	if len(doc.Apps) != 1 || doc.Apps[0].ID != "build" || w.Header().Get("Cache-Control") == "" {
		t.Fatalf("doc = %+v, headers %v", doc, w.Header())
	}

	without, err := NewEmbedded(Config{Issuer: testIssuer})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	without.ServeHTTP(w, httptest.NewRequest(http.MethodGet, appcatalog.WellKnownPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("catalog served without one: %d", w.Code)
	}
}
