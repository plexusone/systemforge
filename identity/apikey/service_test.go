package apikey

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// mockStore implements Store for testing.
type mockStore struct {
	keys     map[string]*APIKey  // prefix -> key
	hashes   map[string]string   // prefix -> hash
	byID     map[uuid.UUID]*APIKey
	byOwner  map[uuid.UUID][]*APIKey
	byOrg    map[uuid.UUID][]*APIKey
	lastUsed map[uuid.UUID]time.Time
}

func newMockStore() *mockStore {
	return &mockStore{
		keys:     make(map[string]*APIKey),
		hashes:   make(map[string]string),
		byID:     make(map[uuid.UUID]*APIKey),
		byOwner:  make(map[uuid.UUID][]*APIKey),
		byOrg:    make(map[uuid.UUID][]*APIKey),
		lastUsed: make(map[uuid.UUID]time.Time),
	}
}

func (m *mockStore) Create(ctx context.Context, key *APIKey, keyHash string) error {
	m.keys[key.Prefix] = key
	m.hashes[key.Prefix] = keyHash
	m.byID[key.ID] = key
	m.byOwner[key.OwnerID] = append(m.byOwner[key.OwnerID], key)
	if key.OrganizationID != nil {
		m.byOrg[*key.OrganizationID] = append(m.byOrg[*key.OrganizationID], key)
	}
	return nil
}

func (m *mockStore) GetByPrefix(ctx context.Context, prefix string) (*APIKey, string, error) {
	key, ok := m.keys[prefix]
	if !ok {
		return nil, "", ErrKeyNotFound
	}
	return key, m.hashes[prefix], nil
}

func (m *mockStore) GetByID(ctx context.Context, id uuid.UUID) (*APIKey, error) {
	key, ok := m.byID[id]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (m *mockStore) ListByOwner(ctx context.Context, ownerID uuid.UUID) ([]*APIKey, error) {
	return m.byOwner[ownerID], nil
}

func (m *mockStore) ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*APIKey, error) {
	return m.byOrg[orgID], nil
}

func (m *mockStore) Update(ctx context.Context, key *APIKey) error {
	m.keys[key.Prefix] = key
	m.byID[key.ID] = key
	return nil
}

func (m *mockStore) Delete(ctx context.Context, id uuid.UUID) error {
	key, ok := m.byID[id]
	if !ok {
		return ErrKeyNotFound
	}
	delete(m.keys, key.Prefix)
	delete(m.hashes, key.Prefix)
	delete(m.byID, id)
	return nil
}

func (m *mockStore) UpdateLastUsed(ctx context.Context, id uuid.UUID, ip string) error {
	key, ok := m.byID[id]
	if !ok {
		return ErrKeyNotFound
	}
	now := time.Now()
	key.LastUsedAt = &now
	key.LastUsedIP = ip
	m.lastUsed[id] = now
	return nil
}

func TestNewService(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	if svc == nil {
		t.Fatal("NewService() returned nil")
	}
}

func TestService_Create(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	ownerID := uuid.New()
	result, err := svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: ownerID,
		Scopes:  []string{"read:users", "write:projects"},
	})

	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if result.Key == "" {
		t.Error("Key should not be empty")
	}

	if result.APIKey == nil {
		t.Fatal("APIKey should not be nil")
	}

	if result.APIKey.Name != "Test Key" {
		t.Errorf("Name = %s, want Test Key", result.APIKey.Name)
	}

	if result.APIKey.OwnerID != ownerID {
		t.Errorf("OwnerID = %s, want %s", result.APIKey.OwnerID, ownerID)
	}

	if len(result.APIKey.Scopes) != 2 {
		t.Errorf("Scopes length = %d, want 2", len(result.APIKey.Scopes))
	}

	// Verify key format
	if !strings.HasPrefix(result.Key, "sf_live_") {
		t.Errorf("Key should start with sf_live_, got %s", result.Key[:20])
	}
}

func TestService_Create_TestEnvironment(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	result, err := svc.Create(context.Background(), CreateKeyRequest{
		Name:        "Test Key",
		OwnerID:     uuid.New(),
		Environment: EnvTest,
	})

	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if !strings.HasPrefix(result.Key, "sf_test_") {
		t.Errorf("Key should start with sf_test_, got prefix %s", result.Key[:20])
	}

	if result.APIKey.Environment != EnvTest {
		t.Errorf("Environment = %s, want test", result.APIKey.Environment)
	}
}

func TestService_Create_WithExpiry(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	expiry := 24 * time.Hour
	result, err := svc.Create(context.Background(), CreateKeyRequest{
		Name:      "Test Key",
		OwnerID:   uuid.New(),
		ExpiresIn: &expiry,
	})

	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if result.APIKey.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil")
	}

	expectedExpiry := time.Now().Add(expiry)
	if result.APIKey.ExpiresAt.Sub(expectedExpiry) > time.Minute {
		t.Error("ExpiresAt should be approximately 24 hours from now")
	}
}

func TestService_Create_WithOrganization(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	orgID := uuid.New()
	result, err := svc.Create(context.Background(), CreateKeyRequest{
		Name:           "Org Key",
		OwnerID:        uuid.New(),
		OrganizationID: &orgID,
	})

	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if result.APIKey.OrganizationID == nil || *result.APIKey.OrganizationID != orgID {
		t.Errorf("OrganizationID = %v, want %s", result.APIKey.OrganizationID, orgID)
	}
}

func TestService_Create_EmptyName(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	_, err := svc.Create(context.Background(), CreateKeyRequest{
		OwnerID: uuid.New(),
	})

	if err == nil {
		t.Error("Create() should error for empty name")
	}
}

func TestService_Create_EmptyOwner(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	_, err := svc.Create(context.Background(), CreateKeyRequest{
		Name: "Test Key",
	})

	if err == nil {
		t.Error("Create() should error for empty owner")
	}
}

func TestService_Create_RestrictedScopes(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store:         store,
		AllowedScopes: []string{"read:users", "read:projects"},
	})

	// Valid scope
	_, err := svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
		Scopes:  []string{"read:users"},
	})
	if err != nil {
		t.Errorf("Create() with valid scope error: %v", err)
	}

	// Invalid scope
	_, err = svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
		Scopes:  []string{"write:users"},
	})
	if err == nil {
		t.Error("Create() should error for invalid scope")
	}
}

func TestService_Validate(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	// Create a key
	result, _ := svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	// Validate it
	apiKey, err := svc.Validate(context.Background(), result.Key)
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	if apiKey.Name != "Test Key" {
		t.Errorf("Name = %s, want Test Key", apiKey.Name)
	}
}

func TestService_Validate_InvalidKey(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	_, err := svc.Validate(context.Background(), "invalid_key")
	if err != ErrInvalidKey {
		t.Errorf("Validate() error = %v, want ErrInvalidKey", err)
	}
}

func TestService_Validate_WrongKey(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	// Create a key
	result, _ := svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	// Modify the key slightly
	wrongKey := result.Key + "x"

	_, err := svc.Validate(context.Background(), wrongKey)
	if err != ErrInvalidKey {
		t.Errorf("Validate() error = %v, want ErrInvalidKey", err)
	}
}

func TestService_Validate_ExpiredKey(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	// Create a key with past expiry
	expiry := -time.Hour
	result, _ := svc.Create(context.Background(), CreateKeyRequest{
		Name:      "Test Key",
		OwnerID:   uuid.New(),
		ExpiresIn: &expiry,
	})

	_, err := svc.Validate(context.Background(), result.Key)
	if err != ErrKeyExpired {
		t.Errorf("Validate() error = %v, want ErrKeyExpired", err)
	}
}

func TestService_Validate_RevokedKey(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	// Create and revoke a key
	result, _ := svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	_ = svc.Revoke(context.Background(), result.APIKey.ID, "test revocation")

	_, err := svc.Validate(context.Background(), result.Key)
	if err != ErrKeyRevoked {
		t.Errorf("Validate() error = %v, want ErrKeyRevoked", err)
	}
}

func TestService_ValidateWithScope(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	result, _ := svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
		Scopes:  []string{"read:users", "write:projects"},
	})

	// Valid scope
	apiKey, err := svc.ValidateWithScope(context.Background(), result.Key, "read:users")
	if err != nil {
		t.Errorf("ValidateWithScope() error: %v", err)
	}
	if apiKey == nil {
		t.Error("APIKey should not be nil")
	}

	// Invalid scope
	_, err = svc.ValidateWithScope(context.Background(), result.Key, "delete:users")
	if err != ErrScopeNotAllowed {
		t.Errorf("ValidateWithScope() error = %v, want ErrScopeNotAllowed", err)
	}
}

func TestService_Revoke(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	result, _ := svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	err := svc.Revoke(context.Background(), result.APIKey.ID, "security concern")
	if err != nil {
		t.Fatalf("Revoke() error: %v", err)
	}

	// Verify revocation
	apiKey, _ := svc.Get(context.Background(), result.APIKey.ID)
	if !apiKey.Revoked {
		t.Error("Revoked = false, want true")
	}
	if apiKey.RevokedReason != "security concern" {
		t.Errorf("RevokedReason = %s, want security concern", apiKey.RevokedReason)
	}
	if apiKey.RevokedAt == nil {
		t.Error("RevokedAt should not be nil")
	}
}

func TestService_Delete(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	result, _ := svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	err := svc.Delete(context.Background(), result.APIKey.ID)
	if err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	// Verify deletion
	_, err = svc.Get(context.Background(), result.APIKey.ID)
	if err != ErrKeyNotFound {
		t.Errorf("Get() after Delete() error = %v, want ErrKeyNotFound", err)
	}
}

func TestService_List(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	ownerID := uuid.New()

	// Create multiple keys
	for range 3 {
		_, _ = svc.Create(context.Background(), CreateKeyRequest{
			Name:    "Test Key",
			OwnerID: ownerID,
		})
	}

	keys, err := svc.List(context.Background(), ownerID)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("List() length = %d, want 3", len(keys))
	}
}

func TestService_ListByOrganization(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	orgID := uuid.New()

	// Create keys for org
	for range 2 {
		_, _ = svc.Create(context.Background(), CreateKeyRequest{
			Name:           "Org Key",
			OwnerID:        uuid.New(),
			OrganizationID: &orgID,
		})
	}

	// Create key for different org
	otherOrg := uuid.New()
	_, _ = svc.Create(context.Background(), CreateKeyRequest{
		Name:           "Other Key",
		OwnerID:        uuid.New(),
		OrganizationID: &otherOrg,
	})

	keys, err := svc.ListByOrganization(context.Background(), orgID)
	if err != nil {
		t.Fatalf("ListByOrganization() error: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("ListByOrganization() length = %d, want 2", len(keys))
	}
}

func TestService_RecordUsage(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store: store,
	})

	result, _ := svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	err := svc.RecordUsage(context.Background(), result.APIKey.ID, "192.168.1.1")
	if err != nil {
		t.Fatalf("RecordUsage() error: %v", err)
	}

	// Verify usage was recorded
	apiKey, _ := svc.Get(context.Background(), result.APIKey.ID)
	if apiKey.LastUsedAt == nil {
		t.Error("LastUsedAt should not be nil")
	}
	if apiKey.LastUsedIP != "192.168.1.1" {
		t.Errorf("LastUsedIP = %s, want 192.168.1.1", apiKey.LastUsedIP)
	}
}

func TestAPIKey_HasScope(t *testing.T) {
	key := &APIKey{
		Scopes: []string{"read:users", "write:projects", "admin:*"},
	}

	tests := []struct {
		scope string
		want  bool
	}{
		{"read:users", true},
		{"write:projects", true},
		{"delete:users", false},
		{"admin:settings", true},  // matches admin:*
		{"admin:users", true},     // matches admin:*
		{"superadmin:all", false}, // doesn't match admin:*
	}

	for _, tt := range tests {
		got := key.HasScope(tt.scope)
		if got != tt.want {
			t.Errorf("HasScope(%s) = %v, want %v", tt.scope, got, tt.want)
		}
	}
}

func TestAPIKey_HasScope_Wildcard(t *testing.T) {
	key := &APIKey{
		Scopes: []string{"*"},
	}

	// Wildcard should match everything
	if !key.HasScope("anything:here") {
		t.Error("* scope should match any scope")
	}
}

func TestAPIKey_HasAnyScope(t *testing.T) {
	key := &APIKey{
		Scopes: []string{"read:users"},
	}

	if !key.HasAnyScope("read:users", "write:users") {
		t.Error("HasAnyScope should return true when key has at least one scope")
	}

	if key.HasAnyScope("write:users", "delete:users") {
		t.Error("HasAnyScope should return false when key has none of the scopes")
	}
}

func TestAPIKey_HasAllScopes(t *testing.T) {
	key := &APIKey{
		Scopes: []string{"read:users", "write:users"},
	}

	if !key.HasAllScopes("read:users", "write:users") {
		t.Error("HasAllScopes should return true when key has all scopes")
	}

	if key.HasAllScopes("read:users", "delete:users") {
		t.Error("HasAllScopes should return false when key is missing a scope")
	}
}

func TestAPIKey_IsExpired(t *testing.T) {
	// No expiry
	key := &APIKey{}
	if key.IsExpired() {
		t.Error("IsExpired() = true for nil ExpiresAt, want false")
	}

	// Future expiry
	future := time.Now().Add(time.Hour)
	key.ExpiresAt = &future
	if key.IsExpired() {
		t.Error("IsExpired() = true for future expiry, want false")
	}

	// Past expiry
	past := time.Now().Add(-time.Hour)
	key.ExpiresAt = &past
	if !key.IsExpired() {
		t.Error("IsExpired() = false for past expiry, want true")
	}
}

func TestAPIKey_IsValid(t *testing.T) {
	key := &APIKey{}

	// Valid (not expired, not revoked)
	if !key.IsValid() {
		t.Error("IsValid() = false for fresh key, want true")
	}

	// Revoked
	key.Revoked = true
	if key.IsValid() {
		t.Error("IsValid() = true for revoked key, want false")
	}

	// Expired
	key.Revoked = false
	past := time.Now().Add(-time.Hour)
	key.ExpiresAt = &past
	if key.IsValid() {
		t.Error("IsValid() = true for expired key, want false")
	}
}

func TestParseEnvironment(t *testing.T) {
	tests := []struct {
		input   string
		want    Environment
		wantErr bool
	}{
		{"live", EnvLive, false},
		{"production", EnvLive, false},
		{"prod", EnvLive, false},
		{"LIVE", EnvLive, false},
		{"test", EnvTest, false},
		{"development", EnvTest, false},
		{"dev", EnvTest, false},
		{"staging", EnvTest, false},
		{"TEST", EnvTest, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, tt := range tests {
		got, err := ParseEnvironment(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseEnvironment(%s) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseEnvironment(%s) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestService_CustomPrefix(t *testing.T) {
	store := newMockStore()
	svc := NewService(ServiceConfig{
		Store:  store,
		Prefix: "myapp",
	})

	result, err := svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if !strings.HasPrefix(result.Key, "myapp_live_") {
		t.Errorf("Key should start with myapp_live_, got %s", result.Key[:20])
	}
}

func TestService_DefaultExpiry(t *testing.T) {
	store := newMockStore()
	defaultExpiry := 30 * 24 * time.Hour // 30 days
	svc := NewService(ServiceConfig{
		Store:         store,
		DefaultExpiry: &defaultExpiry,
	})

	result, err := svc.Create(context.Background(), CreateKeyRequest{
		Name:    "Test Key",
		OwnerID: uuid.New(),
	})

	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if result.APIKey.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil when DefaultExpiry is set")
	}
}
