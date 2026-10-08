package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/identity/apikey"
)

// mockStore implements apikey.Store for testing.
type mockStore struct {
	keys     map[string]*apikey.APIKey
	hashes   map[string]string
	byID     map[uuid.UUID]*apikey.APIKey
	byOwner  map[uuid.UUID][]*apikey.APIKey
	byOrg    map[uuid.UUID][]*apikey.APIKey
	lastUsed map[uuid.UUID]time.Time
}

func newMockStore() *mockStore {
	return &mockStore{
		keys:     make(map[string]*apikey.APIKey),
		hashes:   make(map[string]string),
		byID:     make(map[uuid.UUID]*apikey.APIKey),
		byOwner:  make(map[uuid.UUID][]*apikey.APIKey),
		byOrg:    make(map[uuid.UUID][]*apikey.APIKey),
		lastUsed: make(map[uuid.UUID]time.Time),
	}
}

func (m *mockStore) Create(ctx context.Context, key *apikey.APIKey, keyHash string) error {
	m.keys[key.Prefix] = key
	m.hashes[key.Prefix] = keyHash
	m.byID[key.ID] = key
	m.byOwner[key.OwnerID] = append(m.byOwner[key.OwnerID], key)
	if key.OrganizationID != nil {
		m.byOrg[*key.OrganizationID] = append(m.byOrg[*key.OrganizationID], key)
	}
	return nil
}

func (m *mockStore) GetByPrefix(ctx context.Context, prefix string) (*apikey.APIKey, string, error) {
	key, ok := m.keys[prefix]
	if !ok {
		return nil, "", apikey.ErrKeyNotFound
	}
	return key, m.hashes[prefix], nil
}

func (m *mockStore) GetByID(ctx context.Context, id uuid.UUID) (*apikey.APIKey, error) {
	key, ok := m.byID[id]
	if !ok {
		return nil, apikey.ErrKeyNotFound
	}
	return key, nil
}

func (m *mockStore) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]*apikey.APIKey, error) {
	return m.byOwner[ownerID], nil
}

func (m *mockStore) ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*apikey.APIKey, error) {
	return m.byOrg[orgID], nil
}

func (m *mockStore) Update(ctx context.Context, key *apikey.APIKey) error {
	m.keys[key.Prefix] = key
	m.byID[key.ID] = key
	return nil
}

func (m *mockStore) Delete(ctx context.Context, id uuid.UUID) error {
	key, ok := m.byID[id]
	if !ok {
		return apikey.ErrKeyNotFound
	}
	delete(m.keys, key.Prefix)
	delete(m.hashes, key.Prefix)
	delete(m.byID, id)
	return nil
}

func (m *mockStore) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	key, ok := m.byID[id]
	if !ok {
		return apikey.ErrKeyNotFound
	}
	now := time.Now()
	key.LastUsedAt = &now
	key.LastUsedIP = ip
	m.lastUsed[id] = now
	return nil
}

//nolint:unparam // mockStore returned for tests that need direct store access
func createTestService() (*apikey.Service, *mockStore) {
	store := newMockStore()
	svc := apikey.NewService(apikey.ServiceConfig{
		Store: store,
	})
	return svc, store
}

func TestAPIKeyMiddleware_ValidKey(t *testing.T) {
	svc, _ := createTestService()

	// Create a key
	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
		Scopes:  []string{"read:users"},
	})

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		// Verify API key is in context
		key := GetAPIKey(r.Context())
		if key == nil {
			t.Error("API key should be in context")
		}

		// Verify principal is in context
		principal := GetPrincipal(r.Context())
		if principal == nil {
			t.Fatal("Principal should be in context")
		}
		if principal.Type != "api_key" {
			t.Errorf("Principal.Type = %s, want api_key", principal.Type)
		}

		w.WriteHeader(http.StatusOK)
	})

	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = svc
	config.RecordUsage = false // Disable for test
	middleware := APIKeyMiddleware(config)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+result.Key)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called for valid key")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestAPIKeyMiddleware_NoKey(t *testing.T) {
	svc, _ := createTestService()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called without key")
	})

	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = svc
	middleware := APIKeyMiddleware(config)

	req := httptest.NewRequest("GET", "/api/users", nil)
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAPIKeyMiddleware_InvalidKey(t *testing.T) {
	svc, _ := createTestService()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for invalid key")
	})

	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = svc
	middleware := APIKeyMiddleware(config)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer invalid_key_here")

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAPIKeyMiddleware_RevokedKey(t *testing.T) {
	svc, _ := createTestService()

	// Create and revoke a key
	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})
	_ = svc.Revoke(context.Background(), result.APIKey.ID, "test")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for revoked key")
	})

	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = svc
	middleware := APIKeyMiddleware(config)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+result.Key)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAPIKeyMiddleware_RequiredScopes(t *testing.T) {
	svc, _ := createTestService()

	// Create a key with limited scopes
	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
		Scopes:  []string{"read:users"},
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Require a scope the key doesn't have
	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = svc
	config.RequiredScopes = []string{"write:users"}
	config.RecordUsage = false
	middleware := APIKeyMiddleware(config)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+result.Key)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestAPIKeyMiddleware_AnyScopes(t *testing.T) {
	svc, _ := createTestService()

	// Create a key with one of the required scopes
	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
		Scopes:  []string{"read:users"},
	})

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = svc
	config.AnyScopes = []string{"read:users", "write:users"}
	config.RecordUsage = false
	middleware := APIKeyMiddleware(config)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+result.Key)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called when key has any required scope")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestAPIKeyMiddleware_ApiKeyScheme(t *testing.T) {
	svc, _ := createTestService()

	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = svc
	config.RecordUsage = false
	middleware := APIKeyMiddleware(config)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "ApiKey "+result.Key)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called with ApiKey scheme")
	}
}

func TestAPIKeyMiddleware_QueryParam(t *testing.T) {
	svc, _ := createTestService()

	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = svc
	config.AllowQueryParam = true
	config.RecordUsage = false
	middleware := APIKeyMiddleware(config)

	req := httptest.NewRequest("GET", "/api/users?api_key="+result.Key, nil)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called with query param key")
	}
}

func TestAPIKeyMiddleware_QueryParamDisabled(t *testing.T) {
	svc, _ := createTestService()

	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called when query param is disabled")
	})

	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = svc
	config.AllowQueryParam = false // Default
	middleware := APIKeyMiddleware(config)

	req := httptest.NewRequest("GET", "/api/users?api_key="+result.Key, nil)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAPIKeyMiddleware_CustomErrorHandler(t *testing.T) {
	svc, _ := createTestService()

	customErrorCalled := false
	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = svc
	config.OnError = func(w http.ResponseWriter, r *http.Request, err error) {
		customErrorCalled = true
		http.Error(w, "Custom error", http.StatusTeapot)
	}
	middleware := APIKeyMiddleware(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	})

	req := httptest.NewRequest("GET", "/api/users", nil)
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	if !customErrorCalled {
		t.Error("Custom error handler should be called")
	}
	if rr.Code != http.StatusTeapot {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusTeapot)
	}
}

func TestAPIKeyMiddleware_OnSuccess(t *testing.T) {
	svc, _ := createTestService()

	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	successCalled := false
	config := DefaultAPIKeyMiddlewareConfig()
	config.Service = svc
	config.RecordUsage = false
	config.OnSuccess = func(r *http.Request, key *apikey.APIKey) {
		successCalled = true
		if key.Name != "Test Key" {
			t.Errorf("Key name = %s, want Test Key", key.Name)
		}
	}
	middleware := APIKeyMiddleware(config)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+result.Key)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !successCalled {
		t.Error("OnSuccess should be called")
	}
}

func TestRequireAPIKey(t *testing.T) {
	svc, _ := createTestService()

	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := RequireAPIKey(svc)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+result.Key)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called")
	}
}

func TestRequireAPIKeyWithScopes(t *testing.T) {
	svc, _ := createTestService()

	// Key without required scope
	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
		Scopes:  []string{"read:users"},
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called without required scope")
	})

	middleware := RequireAPIKeyWithScopes(svc, "write:users")

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+result.Key)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestOptionalAPIKey_WithKey(t *testing.T) {
	svc, _ := createTestService()

	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		key := GetAPIKey(r.Context())
		if key == nil {
			t.Error("API key should be in context")
		}

		w.WriteHeader(http.StatusOK)
	})

	middleware := OptionalAPIKey(svc)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+result.Key)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called")
	}
}

func TestOptionalAPIKey_WithoutKey(t *testing.T) {
	svc, _ := createTestService()

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		key := GetAPIKey(r.Context())
		if key != nil {
			t.Error("API key should not be in context")
		}

		w.WriteHeader(http.StatusOK)
	})

	middleware := OptionalAPIKey(svc)

	req := httptest.NewRequest("GET", "/api/users", nil)

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called even without key")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestOptionalAPIKey_InvalidKey(t *testing.T) {
	svc, _ := createTestService()

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		key := GetAPIKey(r.Context())
		if key != nil {
			t.Error("Invalid key should not be in context")
		}

		w.WriteHeader(http.StatusOK)
	})

	middleware := OptionalAPIKey(svc)

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer invalid_key")

	rr := httptest.NewRecorder()
	middleware(handler).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called even with invalid key")
	}
}

func TestRequireScope(t *testing.T) {
	svc, _ := createTestService()

	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
		Scopes:  []string{"read:users"},
	})

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// Chain middleware
	apiKeyMiddleware := RequireAPIKey(svc)
	scopeMiddleware := RequireScope("read:users")

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+result.Key)

	rr := httptest.NewRecorder()
	apiKeyMiddleware(scopeMiddleware(handler)).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called when scope is present")
	}
}

func TestRequireScope_NoPrincipal(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called without principal")
	})

	middleware := RequireScope("read:users")

	req := httptest.NewRequest("GET", "/api/users", nil)
	rr := httptest.NewRecorder()

	middleware(handler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestRequireAnyScope(t *testing.T) {
	svc, _ := createTestService()

	result, _ := svc.Create(context.Background(), apikey.CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
		Scopes:  []string{"read:users"},
	})

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	apiKeyMiddleware := RequireAPIKey(svc)
	scopeMiddleware := RequireAnyScope("read:users", "write:users")

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+result.Key)

	rr := httptest.NewRecorder()
	apiKeyMiddleware(scopeMiddleware(handler)).ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Handler should be called when key has any required scope")
	}
}

func TestPrincipal_HasScope(t *testing.T) {
	principal := &Principal{
		Scopes: []string{"read:users", "write:projects", "admin:*"},
	}

	tests := []struct {
		scope string
		want  bool
	}{
		{"read:users", true},
		{"write:projects", true},
		{"delete:users", false},
		{"admin:settings", true},
		{"admin:users", true},
	}

	for _, tt := range tests {
		got := principal.HasScope(tt.scope)
		if got != tt.want {
			t.Errorf("HasScope(%s) = %v, want %v", tt.scope, got, tt.want)
		}
	}
}

func TestPrincipal_IsAPIKey(t *testing.T) {
	principal := &Principal{Type: "api_key"}
	if !principal.IsAPIKey() {
		t.Error("IsAPIKey() = false, want true")
	}

	principal.Type = "user"
	if principal.IsAPIKey() {
		t.Error("IsAPIKey() = true, want false")
	}
}

func TestPrincipal_IsUser(t *testing.T) {
	principal := &Principal{Type: "user"}
	if !principal.IsUser() {
		t.Error("IsUser() = false, want true")
	}

	principal.Type = "api_key"
	if principal.IsUser() {
		t.Error("IsUser() = true, want false")
	}
}

func TestGetAPIKey_NotSet(t *testing.T) {
	ctx := context.Background()
	key := GetAPIKey(ctx)
	if key != nil {
		t.Error("GetAPIKey() should return nil for empty context")
	}
}

func TestGetPrincipal_NotSet(t *testing.T) {
	ctx := context.Background()
	principal := GetPrincipal(ctx)
	if principal != nil {
		t.Error("GetPrincipal() should return nil for empty context")
	}
}

// TestExtractIPIgnoresForwardingHeaders verifies that the address recorded
// for an API key use cannot be forged with headers.
func TestExtractIPIgnoresForwardingHeaders(t *testing.T) {
	config := DefaultAPIKeyMiddlewareConfig()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.1, 10.0.0.1")
	req.Header.Set("X-Real-IP", "192.168.1.2")

	if ip := extractIP(req, config); ip != "192.0.2.1" {
		t.Errorf("extractIP() = %s, want the peer 192.0.2.1", ip)
	}

	// Behind a proxy, the caller says how to find the client.
	config.IPExtractor = func(*http.Request) string { return "198.51.100.7" }
	if ip := extractIP(req, config); ip != "198.51.100.7" {
		t.Errorf("extractIP() with an extractor = %s", ip)
	}
}

func TestExtractIP_RemoteAddr(t *testing.T) {
	config := DefaultAPIKeyMiddlewareConfig()

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	ip := extractIP(req, config)
	if ip != "192.168.1.1" {
		t.Errorf("extractIP() = %s, want 192.168.1.1", ip)
	}
}

func TestExtractIP_CustomExtractor(t *testing.T) {
	config := DefaultAPIKeyMiddlewareConfig()
	config.IPExtractor = func(r *http.Request) string {
		return "custom-ip"
	}

	req := httptest.NewRequest("GET", "/", nil)

	ip := extractIP(req, config)
	if ip != "custom-ip" {
		t.Errorf("extractIP() = %s, want custom-ip", ip)
	}
}
