package contract

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/identity/ent/enttest"
)

// TestInternalErrorTextIsNotSent expects a database failure to answer a
// generic 500 that carries none of the driver's error text.
func TestInternalErrorTextIsNotSent(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	provider, err := NewProvider(&Config{
		AppID:                          "test-app",
		DisplayName:                    "Test",
		Version:                        "1",
		BaseURL:                        "/systemforge",
		Capabilities:                   []Capability{CapabilityIdentity, CapabilityRBAC, CapabilityAudit},
		AllowUnauthenticatedStandalone: true,
	}, client)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	api, err := NewAPI(provider)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	// A closed client fails every query with the driver's text.
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for _, path := range []string{
		"/systemforge/identity/principals",
		"/systemforge/identity/tenants",
		"/systemforge/identity/principals/" + uuid.NewString(),
	} {
		w := httptest.NewRecorder()
		api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusInternalServerError {
			t.Errorf("GET %s = %d, want 500", path, w.Code)
		}
		body := strings.ToLower(w.Body.String())
		for _, leak := range []string{"sql", "closed", "database"} {
			if strings.Contains(body, leak) {
				t.Errorf("GET %s body leaks %q: %s", path, leak, w.Body.String())
			}
		}
	}
}

func TestToContractErrorHidesErrorText(t *testing.T) {
	got := ToContractError(errors.New(`pq: relation "secret" does not exist`))
	if got.Status() != http.StatusInternalServerError || strings.Contains(got.Error(), "secret") {
		t.Errorf("ToContractError = %d %q, want a 500 without the error text", got.Status(), got.Error())
	}
	wrapped := ErrUnauthorized("nope")
	if ToContractError(wrapped) != wrapped {
		t.Error("contract error not passed through")
	}
}
