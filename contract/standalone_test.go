package contract

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func newStandaloneTestAPI(t *testing.T, allow bool) *API {
	t.Helper()
	provider, err := NewProvider(&Config{
		AppID:                          "test-app",
		DisplayName:                    "Test",
		Version:                        "1",
		BaseURL:                        "/systemforge",
		Capabilities:                   []Capability{CapabilityIdentity, CapabilityRBAC, CapabilityAudit},
		AllowUnauthenticatedStandalone: allow,
	}, nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	api, err := NewAPI(provider)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	return api
}

func get(api *API, path string) int {
	w := httptest.NewRecorder()
	api.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w.Code
}

// TestStandaloneRefusesOperationsByDefault verifies that an application that
// has not joined a federation does not answer identity, policy or audit
// requests without credentials unless it opts in.
func TestStandaloneRefusesOperationsByDefault(t *testing.T) {
	api := newStandaloneTestAPI(t, false)

	for _, path := range []string{
		"/systemforge/identity/principals",
		"/systemforge/identity/tenants",
		"/systemforge/policy/roles",
		"/systemforge/policy/permissions",
		"/systemforge/audit/stream/config",
	} {
		if got := get(api, path); got != http.StatusForbidden {
			t.Errorf("GET %s = %d, want %d", path, got, http.StatusForbidden)
		}
	}
}

// TestStandaloneKeepsDiscoveryOpen verifies that the meta and health
// endpoints stay reachable, so a standalone application can still be probed.
func TestStandaloneKeepsDiscoveryOpen(t *testing.T) {
	api := newStandaloneTestAPI(t, false)

	for _, path := range []string{
		"/systemforge/meta",
		"/systemforge/health",
		"/systemforge/health/federation",
	} {
		if got := get(api, path); got != http.StatusOK {
			t.Errorf("GET %s = %d, want %d", path, got, http.StatusOK)
		}
	}
}

func TestStandaloneOptInAllowsOperations(t *testing.T) {
	api := newStandaloneTestAPI(t, true)
	if err := api.checkPermission(context.Background(), PermissionIdentityRead); err != nil {
		t.Fatalf("opted-in standalone refused: %v", err)
	}
}

// TestLeavingFederationClosesOperations verifies that returning to standalone
// mode does not reopen the operations.
func TestLeavingFederationClosesOperations(t *testing.T) {
	api := newStandaloneTestAPI(t, false)
	state := api.Provider().FederationState()

	state.SetFederated(uuid.New())
	if err := api.checkPermission(context.Background(), PermissionIdentityRead); err == nil {
		t.Fatal("federated request with no permission was allowed")
	}
	state.SetStandalone()
	if err := api.checkPermission(context.Background(), PermissionIdentityRead); err == nil {
		t.Fatal("operations reopened after leaving the federation")
	}
}
