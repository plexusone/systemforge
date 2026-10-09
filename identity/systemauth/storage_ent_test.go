package systemauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"

	_ "github.com/mattn/go-sqlite3"
)

// createTestOwner creates a service principal to own test OAuth clients and
// returns its ID.
func createTestOwner(t *testing.T, client *ent.Client) uuid.UUID {
	t.Helper()
	p, err := client.Principal.Create().
		SetType(principal.TypeService).
		SetIdentifier("test-owner-" + uuid.New().String()[:8]).
		SetDisplayName("Test Owner").
		Save(context.Background())
	if err != nil {
		t.Fatalf("Failed to create test owner: %v", err)
	}
	return p.ID
}

func TestEntStorageClient(t *testing.T) {
	// Create an in-memory SQLite database for testing
	client := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer func() { _ = client.Close() }()

	// Create a test user for owner_id
	ownerID := createTestOwner(t, client)
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

	ownerID := createTestOwner(t, client)
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

	ownerID := createTestOwner(t, client)
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

	ownerID := createTestOwner(t, client)
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

// TestEntStorageCreateClientConstraintErrors verifies that only a genuine
// duplicate client ID is reported as ErrClientExists; other constraint
// failures, such as an owner that does not exist, surface as themselves.
func TestEntStorageCreateClientConstraintErrors(t *testing.T) {
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	ctx := context.Background()
	newClient := func() *Client {
		return &Client{
			ID:           "client-" + uuid.NewString()[:8],
			Type:         ClientTypePublic,
			Name:         "Client",
			RedirectURIs: []string{"https://example.com/callback"},
			GrantTypes:   []string{"authorization_code"},
		}
	}

	storage := NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))
	c := newClient()
	if err := storage.CreateClient(ctx, c); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if err := storage.CreateClient(ctx, c); !errors.Is(err, ErrClientExists) {
		t.Errorf("duplicate CreateClient error = %v, want ErrClientExists", err)
	}

	orphan := NewEntStorage(db, WithDefaultOwner(uuid.New()))
	err := orphan.CreateClient(ctx, newClient())
	if err == nil {
		t.Fatal("CreateClient with a nonexistent owner succeeded")
	}
	if errors.Is(err, ErrClientExists) {
		t.Errorf("nonexistent owner reported as ErrClientExists: %v", err)
	}
}

// TestEntStorageClientAssertionReplay verifies that a used client-assertion
// JWT ID is recorded and then rejected, which private_key_jwt client
// authentication relies on.
func TestEntStorageClientAssertionReplay(t *testing.T) {
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	s := NewEntStorage(db)
	ctx := context.Background()
	if err := s.SetClientAssertionJWT(ctx, "jti-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetClientAssertionJWT: %v", err)
	}
	if err := s.ClientAssertionJWTValid(ctx, "jti-1"); !errors.Is(err, fosite.ErrJTIKnown) {
		t.Errorf("replayed JTI error = %v, want ErrJTIKnown", err)
	}
}

// TestRevokeSubjectTokensRecordsAccessChange verifies that revoking a
// principal's tokens records and announces an access change, and that a
// subject that is not a principal (a client) records none (ADR-010).
func TestRevokeSubjectTokensRecordsAccessChange(t *testing.T) {
	ctx := context.Background()
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	defer func() { _ = client.Close() }()
	var announced []accesschange.Change
	storage := NewEntStorage(client, WithEntAccessChangeSink(accesschange.SinkFunc(func(c accesschange.Change) {
		announced = append(announced, c)
	})))
	pid := createTestOwner(t, client)

	if err := storage.RevokeSubjectTokens(ctx, "some-client-id"); err != nil {
		t.Fatal(err)
	}
	if err := storage.RevokeSubjectTokens(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if len(announced) != 0 {
		t.Fatalf("non-principal subjects announced %+v", announced)
	}
	if err := storage.RevokeSubjectTokens(ctx, pid.String()); err != nil {
		t.Fatal(err)
	}
	if len(announced) != 1 || announced[0].PrincipalID != pid || announced[0].Reason != accesschange.SessionsRevoked {
		t.Fatalf("announced = %+v", announced)
	}
	if stored, err := accesschange.Since(ctx, client, time.Time{}, 0); err != nil || len(stored) != 1 {
		t.Errorf("stored = %+v, %v", stored, err)
	}
}
