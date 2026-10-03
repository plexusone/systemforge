package systemauth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Providers holds all provider implementations for SystemAuth.
// This provides a unified way to access identity, authentication, and OAuth services.
type Providers struct {
	Identity       IdentityProvider
	Authentication AuthenticationProvider
	OAuth          OAuthProvider
	OAuthClients   OAuthClientStore
}

// ProvidersOption configures the embedded providers.
type ProvidersOption func(*providersConfig)

type providersConfig struct {
	sessionDuration  time.Duration
	passwordVerifier func(ctx context.Context, identityID uuid.UUID, password string) (bool, error)
}

// WithProviderSessionDuration sets the session duration for the auth provider.
func WithProviderSessionDuration(d time.Duration) ProvidersOption {
	return func(c *providersConfig) {
		c.sessionDuration = d
	}
}

// WithProviderPasswordVerifier sets the password verification function.
func WithProviderPasswordVerifier(verifier func(ctx context.Context, identityID uuid.UUID, password string) (bool, error)) ProvidersOption {
	return func(c *providersConfig) {
		c.passwordVerifier = verifier
	}
}

// NewProviders creates all embedded providers from a SystemAuth Server.
// This is the simplest way to get all provider implementations.
//
// Example:
//
//	server, _ := systemauth.NewEmbedded(cfg)
//	providers := systemauth.NewProviders(server)
//
//	// Use providers
//	identity, _ := providers.Identity.GetIdentity(ctx, userID)
//	session, _ := providers.Authentication.ValidateSession(ctx, token)
//	userInfo, _ := providers.OAuth.UserInfo(ctx, accessToken)
func NewProviders(server *Server, opts ...ProvidersOption) *Providers {
	cfg := &providersConfig{
		sessionDuration: 24 * time.Hour,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	identityProvider := NewEmbeddedIdentityProvider(server.storage)

	authOpts := []EmbeddedAuthProviderOption{
		WithSessionDuration(cfg.sessionDuration),
	}
	if cfg.passwordVerifier != nil {
		authOpts = append(authOpts, WithPasswordVerifier(cfg.passwordVerifier))
	}

	return &Providers{
		Identity:       identityProvider,
		Authentication: NewEmbeddedAuthProvider(identityProvider, authOpts...),
		OAuth:          NewEmbeddedOAuthProvider(server),
		OAuthClients:   NewEmbeddedOAuthClientStore(server.storage),
	}
}

// NewProvidersFromStorage creates providers directly from storage.
// Use this when you don't need the full OAuth server functionality.
//
// Example:
//
//	storage := systemauth.NewMemoryStorage()
//	providers := systemauth.NewProvidersFromStorage(storage)
func NewProvidersFromStorage(storage Storage, opts ...ProvidersOption) *Providers {
	cfg := &providersConfig{
		sessionDuration: 24 * time.Hour,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	identityProvider := NewEmbeddedIdentityProvider(storage)

	authOpts := []EmbeddedAuthProviderOption{
		WithSessionDuration(cfg.sessionDuration),
	}
	if cfg.passwordVerifier != nil {
		authOpts = append(authOpts, WithPasswordVerifier(cfg.passwordVerifier))
	}

	return &Providers{
		Identity:       identityProvider,
		Authentication: NewEmbeddedAuthProvider(identityProvider, authOpts...),
		OAuth:          nil, // No OAuth server available
		OAuthClients:   NewEmbeddedOAuthClientStore(storage),
	}
}
