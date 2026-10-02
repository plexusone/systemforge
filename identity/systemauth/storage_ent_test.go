package systemauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"

	_ "github.com/mattn/go-sqlite3"
)

// createTestUser creates a test user and returns its ID.
func createTestUser(t *testing.T, client *ent.Client) uuid.UUID {
	t.Helper()
	user, err := client.User.Create().
		SetEmail("test-" + uuid.New().String()[:8] + "@example.com").
		SetName("Test User").
		Save(context.Background())
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}
	return user.ID
}

func TestEntStorageClient(t *testing.T) {
	// Create an in-memory SQLite database for testing
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer func() { _ = client.Close() }()

	// Create a test user for owner_id
	ownerID := createTestUser(t, client)
	storage := NewEntStorage(client, WithDefaultOwner(ownerID))
	ctx := context.Background()

	// Test CreateClient
	testClient := &Client{
		ID:           "test-client-" + uuid.New().String()[:8],
		Type:         ClientTypeConfidential,
		Name:         "Test Client",
		Description:  "A test client",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile"},
	}

	err := storage.CreateClient(ctx, testClient)
	if err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	// Test GetClientByID
	retrieved, err := storage.GetClientByID(ctx, testClient.ID)
	if err != nil {
		t.Fatalf("GetClientByID failed: %v", err)
	}

	if retrieved.ID != testClient.ID {
		t.Errorf("Expected client ID %s, got %s", testClient.ID, retrieved.ID)
	}
	if retrieved.Name != testClient.Name {
		t.Errorf("Expected client name %s, got %s", testClient.Name, retrieved.Name)
	}

	// Test GetClient (Fosite interface)
	fositeClient, err := storage.GetClient(ctx, testClient.ID)
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}

	if fositeClient.GetID() != testClient.ID {
		t.Errorf("Expected client ID %s, got %s", testClient.ID, fositeClient.GetID())
	}

	// Test ListClients
	clients, err := storage.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients failed: %v", err)
	}

	if len(clients) != 1 {
		t.Errorf("Expected 1 client, got %d", len(clients))
	}

	// Test UpdateClient
	testClient.Name = "Updated Test Client"
	err = storage.UpdateClient(ctx, testClient)
	if err != nil {
		t.Fatalf("UpdateClient failed: %v", err)
	}

	retrieved, err = storage.GetClientByID(ctx, testClient.ID)
	if err != nil {
		t.Fatalf("GetClientByID after update failed: %v", err)
	}

	if retrieved.Name != "Updated Test Client" {
		t.Errorf("Expected updated name, got %s", retrieved.Name)
	}

	// Test DeleteClient
	err = storage.DeleteClient(ctx, testClient.ID)
	if err != nil {
		t.Fatalf("DeleteClient failed: %v", err)
	}

	// Verify client is no longer retrievable (soft delete)
	_, err = storage.GetClient(ctx, testClient.ID)
	if err != fosite.ErrNotFound {
		t.Errorf("Expected ErrNotFound after delete, got %v", err)
	}
}

func TestEntStoragePublicClient(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer func() { _ = client.Close() }()

	ownerID := createTestUser(t, client)
	storage := NewEntStorage(client, WithDefaultOwner(ownerID))
	ctx := context.Background()

	// Create a public client
	publicClient := &Client{
		ID:           "public-client-" + uuid.New().String()[:8],
		Type:         ClientTypePublic,
		Name:         "Public SPA Client",
		RedirectURIs: []string{"https://spa.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "profile"},
	}

	err := storage.CreateClient(ctx, publicClient)
	if err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	// Verify it's stored as public
	retrieved, err := storage.GetClientByID(ctx, publicClient.ID)
	if err != nil {
		t.Fatalf("GetClientByID failed: %v", err)
	}

	if !retrieved.IsPublic() {
		t.Error("Expected client to be public")
	}
}

func TestEntStorageClientNotFound(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer func() { _ = client.Close() }()

	storage := NewEntStorage(client)
	ctx := context.Background()
	// Note: No owner needed for this test as we're only querying

	// Test GetClient with non-existent ID
	_, err := storage.GetClient(ctx, "non-existent-client")
	if err != fosite.ErrNotFound {
		t.Errorf("Expected ErrNotFound, got %v", err)
	}

	// Test GetClientByID with non-existent ID
	_, err = storage.GetClientByID(ctx, "non-existent-client")
	if err != ErrClientNotFound {
		t.Errorf("Expected ErrClientNotFound, got %v", err)
	}
}

func TestEntStorageAccessToken(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer func() { _ = client.Close() }()

	ownerID := createTestUser(t, client)
	storage := NewEntStorage(client, WithDefaultOwner(ownerID))
	ctx := context.Background()

	// Create a client first
	testClient := &Client{
		ID:           "token-test-client-" + uuid.New().String()[:8],
		Type:         ClientTypeConfidential,
		Name:         "Token Test Client",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"read", "write"},
	}

	err := storage.CreateClient(ctx, testClient)
	if err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	// Create a mock session - for client_credentials, no subject (user)
	session := &fosite.DefaultSession{
		Subject: "", // Empty for client_credentials flow
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken: time.Now().Add(15 * time.Minute),
		},
	}

	// Create a request
	req := fosite.NewRequest()
	req.Client = testClient
	req.SetSession(session)
	req.GrantScope("read")

	// Verify client was created correctly
	_, err = storage.GetClientByID(ctx, testClient.ID)
	if err != nil {
		t.Fatalf("Client not found after creation: %v", err)
	}

	// Test CreateAccessTokenSession
	tokenSignature := "test-access-token-" + uuid.New().String()[:8]
	err = storage.CreateAccessTokenSession(ctx, tokenSignature, req)
	if err != nil {
		// Unwrap to get the underlying error
		unwrapped := err
		for {
			inner := errors.Unwrap(unwrapped)
			if inner == nil {
				break
			}
			unwrapped = inner
		}
		t.Fatalf("CreateAccessTokenSession failed: %v (underlying: %v)", err, unwrapped)
	}

	// Test GetAccessTokenSession
	retrieved, err := storage.GetAccessTokenSession(ctx, tokenSignature, session)
	if err != nil {
		t.Fatalf("GetAccessTokenSession failed: %v", err)
	}

	if retrieved.GetClient().GetID() != testClient.ID {
		t.Errorf("Expected client ID %s, got %s", testClient.ID, retrieved.GetClient().GetID())
	}

	// Test DeleteAccessTokenSession
	err = storage.DeleteAccessTokenSession(ctx, tokenSignature)
	if err != nil {
		t.Fatalf("DeleteAccessTokenSession failed: %v", err)
	}

	// Verify token is deleted
	_, err = storage.GetAccessTokenSession(ctx, tokenSignature, session)
	if err != fosite.ErrNotFound {
		t.Errorf("Expected ErrNotFound after delete, got %v", err)
	}
}

func TestEntStorageRefreshToken(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer func() { _ = client.Close() }()

	ownerID := createTestUser(t, client)
	storage := NewEntStorage(client, WithDefaultOwner(ownerID))
	ctx := context.Background()

	// Create a client first
	testClient := &Client{
		ID:           "refresh-test-client-" + uuid.New().String()[:8],
		Type:         ClientTypeConfidential,
		Name:         "Refresh Test Client",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "offline_access"},
	}

	err := storage.CreateClient(ctx, testClient)
	if err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	// Create a mock session - use ownerID as subject since user exists in DB
	session := &fosite.DefaultSession{
		Subject: ownerID.String(),
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:  time.Now().Add(15 * time.Minute),
			fosite.RefreshToken: time.Now().Add(7 * 24 * time.Hour),
		},
	}

	// Create a request
	req := fosite.NewRequest()
	req.Client = testClient
	req.SetSession(session)
	req.GrantScope("openid")
	req.GrantScope("offline_access")

	// Test CreateRefreshTokenSession
	refreshSignature := "test-refresh-token-" + uuid.New().String()[:8]
	accessSignature := "test-access-for-refresh-" + uuid.New().String()[:8]
	err = storage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, req)
	if err != nil {
		t.Fatalf("CreateRefreshTokenSession failed: %v", err)
	}

	// Test GetRefreshTokenSession
	retrieved, err := storage.GetRefreshTokenSession(ctx, refreshSignature, session)
	if err != nil {
		t.Fatalf("GetRefreshTokenSession failed: %v", err)
	}

	if retrieved.GetClient().GetID() != testClient.ID {
		t.Errorf("Expected client ID %s, got %s", testClient.ID, retrieved.GetClient().GetID())
	}

	// Test DeleteRefreshTokenSession (soft delete)
	err = storage.DeleteRefreshTokenSession(ctx, refreshSignature)
	if err != nil {
		t.Fatalf("DeleteRefreshTokenSession failed: %v", err)
	}

	// Verify token is revoked
	_, err = storage.GetRefreshTokenSession(ctx, refreshSignature, session)
	if err != fosite.ErrInactiveToken {
		t.Errorf("Expected ErrInactiveToken after delete, got %v", err)
	}
}

func TestArgon2idDecoding(t *testing.T) {
	// Test hash decoding with a valid Argon2id hash
	// Format: $argon2id$v=19$m=65536,t=3,p=4$<base64_salt>$<base64_hash>
	validHash := "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$cmFuZG9taGFzaHZhbHVl"

	params, salt, hash, err := decodeArgon2idHash(validHash)
	if err != nil {
		t.Fatalf("decodeArgon2idHash failed: %v", err)
	}

	if params.memory != 65536 {
		t.Errorf("Expected memory 65536, got %d", params.memory)
	}
	if params.time != 3 {
		t.Errorf("Expected time 3, got %d", params.time)
	}
	if params.parallelism != 4 {
		t.Errorf("Expected parallelism 4, got %d", params.parallelism)
	}
	if len(salt) == 0 {
		t.Error("Expected non-empty salt")
	}
	if len(hash) == 0 {
		t.Error("Expected non-empty hash")
	}

	// Test invalid formats
	invalidFormats := []string{
		"not-a-hash",
		"$argon2i$v=19$m=65536,t=3,p=4$salt$hash",       // wrong algorithm
		"$argon2id$v=18$m=65536,t=3,p=4$salt$hash",      // wrong version
		"$argon2id$v=19$m=65536,t=3,p=4",                // missing parts
		"$argon2id$v=19$m=65536,t=3,p=4$!!!$hash",       // invalid base64
		"$argon2id$v=19$m=65536,t=3,p=4$salt$!!!",       // invalid base64
		"$argon2id$v=19$invalid$salt$hash",              // invalid params
	}

	for _, invalid := range invalidFormats {
		_, _, _, err := decodeArgon2idHash(invalid)
		if err == nil {
			t.Errorf("Expected error for invalid hash: %s", invalid)
		}
	}
}
