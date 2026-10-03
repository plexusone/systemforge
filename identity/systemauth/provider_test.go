package systemauth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEmbeddedIdentityProvider(t *testing.T) {
	storage := NewMemoryStorage()
	provider := NewEmbeddedIdentityProvider(storage)
	ctx := context.Background()

	// Create identity
	identity := &Identity{
		State: IdentityStateActive,
		Traits: IdentityTraits{
			Email:      "test@example.com",
			Name:       "Test User",
			GivenName:  "Test",
			FamilyName: "User",
		},
	}

	err := provider.CreateIdentity(ctx, identity)
	if err != nil {
		t.Fatalf("CreateIdentity failed: %v", err)
	}

	if identity.ID == uuid.Nil {
		t.Error("expected identity ID to be set")
	}

	// Get identity by ID
	retrieved, err := provider.GetIdentity(ctx, identity.ID)
	if err != nil {
		t.Fatalf("GetIdentity failed: %v", err)
	}
	if retrieved.Traits.Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got '%s'", retrieved.Traits.Email)
	}

	// Get identity by email
	retrieved, err = provider.GetIdentityByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("GetIdentityByEmail failed: %v", err)
	}
	if retrieved.ID != identity.ID {
		t.Error("retrieved identity has different ID")
	}

	// Update identity
	identity.Traits.Name = "Updated Name"
	err = provider.UpdateIdentity(ctx, identity)
	if err != nil {
		t.Fatalf("UpdateIdentity failed: %v", err)
	}

	retrieved, _ = provider.GetIdentity(ctx, identity.ID)
	if retrieved.Traits.Name != "Updated Name" {
		t.Errorf("expected name 'Updated Name', got '%s'", retrieved.Traits.Name)
	}

	// Delete identity
	err = provider.DeleteIdentity(ctx, identity.ID)
	if err != nil {
		t.Fatalf("DeleteIdentity failed: %v", err)
	}

	_, err = provider.GetIdentity(ctx, identity.ID)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestEmbeddedAuthProvider(t *testing.T) {
	storage := NewMemoryStorage()
	identityProvider := NewEmbeddedIdentityProvider(storage)
	ctx := context.Background()

	// Create a test identity
	identity := &Identity{
		State: IdentityStateActive,
		Traits: IdentityTraits{
			Email: "auth@example.com",
			Name:  "Auth User",
		},
	}
	err := identityProvider.CreateIdentity(ctx, identity)
	if err != nil {
		t.Fatalf("CreateIdentity failed: %v", err)
	}

	// Create auth provider with password verifier
	authProvider := NewEmbeddedAuthProvider(
		identityProvider,
		WithSessionDuration(time.Hour),
		WithPasswordVerifier(func(ctx context.Context, id uuid.UUID, password string) (bool, error) {
			return password == "correct-password", nil
		}),
	)

	// Test authentication with correct password
	session, err := authProvider.Authenticate(ctx, &AuthenticateRequest{
		Method:     AuthMethodPassword,
		Identifier: "auth@example.com",
		Password:   "correct-password",
	})
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if session.Token == "" {
		t.Error("expected session token")
	}
	if session.IdentityID != identity.ID {
		t.Error("session has wrong identity ID")
	}

	// Test authentication with wrong password
	_, err = authProvider.Authenticate(ctx, &AuthenticateRequest{
		Method:     AuthMethodPassword,
		Identifier: "auth@example.com",
		Password:   "wrong-password",
	})
	if err != ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}

	// Test session validation
	validated, err := authProvider.ValidateSession(ctx, session.Token)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}
	if !validated.Active {
		t.Error("expected session to be active")
	}

	// Test session listing
	sessions, err := authProvider.ListSessions(ctx, identity.ID)
	if err != nil {
		t.Fatalf("ListSessions failed: %v", err)
	}
	if len(sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessions))
	}

	// Test session revocation
	err = authProvider.RevokeSession(ctx, session.Token)
	if err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}

	_, err = authProvider.ValidateSession(ctx, session.Token)
	if err != ErrSessionRevoked {
		t.Errorf("expected ErrSessionRevoked, got %v", err)
	}
}

func TestEmbeddedOAuthClientStore(t *testing.T) {
	storage := NewMemoryStorage()
	store := NewEmbeddedOAuthClientStore(storage)
	ctx := context.Background()

	// Create client
	client := &OAuthClient{
		ClientID:      "test-client",
		ClientSecret:  "test-secret",
		ClientName:    "Test Client",
		RedirectURIs:  []string{"https://example.com/callback"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scope:         "openid profile email",
		Public:        false,
	}

	err := store.CreateClient(ctx, client)
	if err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	// Get client
	retrieved, err := store.GetClient(ctx, "test-client")
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}
	if retrieved.ClientName != "Test Client" {
		t.Errorf("expected 'Test Client', got '%s'", retrieved.ClientName)
	}
	if retrieved.Public {
		t.Error("expected client to be confidential (not public)")
	}

	// Update client
	client.ClientName = "Updated Client"
	err = store.UpdateClient(ctx, client)
	if err != nil {
		t.Fatalf("UpdateClient failed: %v", err)
	}

	retrieved, _ = store.GetClient(ctx, "test-client")
	if retrieved.ClientName != "Updated Client" {
		t.Errorf("expected 'Updated Client', got '%s'", retrieved.ClientName)
	}

	// List clients
	clients, err := store.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients failed: %v", err)
	}
	if len(clients) != 1 {
		t.Errorf("expected 1 client, got %d", len(clients))
	}

	// Delete client
	err = store.DeleteClient(ctx, "test-client")
	if err != nil {
		t.Fatalf("DeleteClient failed: %v", err)
	}

	_, err = store.GetClient(ctx, "test-client")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestNewProviders(t *testing.T) {
	cfg := Config{
		Issuer: "https://test.example.com",
	}

	server, err := NewEmbedded(cfg)
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	providers := NewProviders(server,
		WithProviderSessionDuration(2*time.Hour),
	)

	if providers.Identity == nil {
		t.Error("expected Identity provider")
	}
	if providers.Authentication == nil {
		t.Error("expected Authentication provider")
	}
	if providers.OAuth == nil {
		t.Error("expected OAuth provider")
	}
	if providers.OAuthClients == nil {
		t.Error("expected OAuthClients store")
	}
}

func TestNewProvidersFromStorage(t *testing.T) {
	storage := NewMemoryStorage()

	providers := NewProvidersFromStorage(storage,
		WithProviderSessionDuration(2*time.Hour),
	)

	if providers.Identity == nil {
		t.Error("expected Identity provider")
	}
	if providers.Authentication == nil {
		t.Error("expected Authentication provider")
	}
	if providers.OAuth != nil {
		t.Error("expected OAuth to be nil when created from storage only")
	}
	if providers.OAuthClients == nil {
		t.Error("expected OAuthClients store")
	}
}
