package systemauth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"
)

// EmbeddedOAuthProvider implements OAuthProvider using Fosite.
type EmbeddedOAuthProvider struct {
	server *Server
}

// NewEmbeddedOAuthProvider creates an OAuthProvider backed by a SystemAuth Server.
func NewEmbeddedOAuthProvider(server *Server) *EmbeddedOAuthProvider {
	return &EmbeddedOAuthProvider{server: server}
}

// Authorize implements OAuthProvider.
// Note: This is typically handled by the HTTP handler; this method is for programmatic access.
func (p *EmbeddedOAuthProvider) Authorize(ctx context.Context, req *OAuthAuthorizeRequest) (*OAuthAuthorizeResponse, error) {
	// Build the authorization URL for redirect
	params := url.Values{
		"client_id":     {req.ClientID},
		"redirect_uri":  {req.RedirectURI},
		"response_type": {req.ResponseType},
		"scope":         {req.Scope},
		"state":         {req.State},
	}

	if req.Nonce != "" {
		params.Set("nonce", req.Nonce)
	}
	if req.CodeChallenge != "" {
		params.Set("code_challenge", req.CodeChallenge)
		params.Set("code_challenge_method", req.CodeChallengeMethod)
	}

	authURL := p.server.config.Issuer + "/oauth/authorize?" + params.Encode()

	return &OAuthAuthorizeResponse{
		RedirectTo: authURL,
	}, nil
}

// Token implements OAuthProvider.
// Note: This is typically handled by the HTTP handler; this method is for programmatic access.
func (p *EmbeddedOAuthProvider) Token(ctx context.Context, req *OAuthTokenRequest) (*OAuthTokenResponse, error) {
	// This would need to create an HTTP request to the token endpoint
	// For now, return an error indicating to use the HTTP endpoint
	return nil, errors.New("use HTTP token endpoint for token requests")
}

// Introspect implements OAuthProvider.
func (p *EmbeddedOAuthProvider) Introspect(ctx context.Context, token string, tokenTypeHint string) (*OAuthIntrospection, error) {
	session := p.server.Session("")

	tokenType := fosite.AccessToken
	if tokenTypeHint == "refresh_token" {
		tokenType = fosite.RefreshToken
	}

	_, ar, err := p.server.oauth2.IntrospectToken(ctx, token, tokenType, session)
	if err != nil {
		// Token is not active
		return &OAuthIntrospection{Active: false}, nil
	}

	// Build introspection response
	introspection := &OAuthIntrospection{
		Active:    true,
		Scope:     strings.Join(ar.GetGrantedScopes(), " "),
		ClientID:  ar.GetClient().GetID(),
		TokenType: "Bearer",
		Sub:       ar.GetSession().GetSubject(),
		Iss:       p.server.config.Issuer,
	}

	// Add expiration if available
	if expiresAt := ar.GetSession().GetExpiresAt(fosite.AccessToken); !expiresAt.IsZero() {
		introspection.Exp = expiresAt.Unix()
	}

	return introspection, nil
}

// Revoke implements OAuthProvider.
func (p *EmbeddedOAuthProvider) Revoke(ctx context.Context, token string, tokenTypeHint string) error {
	// Fosite handles revocation via the revocation endpoint
	// For programmatic access, we'd need to access storage directly
	return p.server.storage.RevokeAccessToken(ctx, token)
}

// UserInfo implements OAuthProvider.
func (p *EmbeddedOAuthProvider) UserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error) {
	session := p.server.Session("")

	_, ar, err := p.server.oauth2.IntrospectToken(ctx, accessToken, fosite.AccessToken, session)
	if err != nil {
		return nil, errors.New("invalid access token")
	}

	subject := ar.GetSession().GetSubject()

	// Get user claims from session provider
	claims := p.server.sessionProvider.GetUserClaims(ctx, subject, ar.GetGrantedScopes())

	userInfo := &OAuthUserInfo{
		Sub: subject,
	}

	// Map claims to UserInfo fields
	if name, ok := claims["name"].(string); ok {
		userInfo.Name = name
	}
	if givenName, ok := claims["given_name"].(string); ok {
		userInfo.GivenName = givenName
	}
	if familyName, ok := claims["family_name"].(string); ok {
		userInfo.FamilyName = familyName
	}
	if email, ok := claims["email"].(string); ok {
		userInfo.Email = email
	}
	if emailVerified, ok := claims["email_verified"].(bool); ok {
		userInfo.EmailVerified = emailVerified
	}
	if picture, ok := claims["picture"].(string); ok {
		userInfo.Picture = picture
	}
	if locale, ok := claims["locale"].(string); ok {
		userInfo.Locale = locale
	}

	return userInfo, nil
}

// GetConsentRequest implements OAuthProvider.
// This is used for the consent flow when separating login/consent UI.
func (p *EmbeddedOAuthProvider) GetConsentRequest(ctx context.Context, challenge string) (*OAuthConsentRequest, error) {
	// In the embedded implementation, consent is handled inline
	// This would be used when integrating with external consent UI
	return nil, errors.New("consent flow not implemented for embedded provider; use HTTP endpoints")
}

// AcceptConsent implements OAuthProvider.
func (p *EmbeddedOAuthProvider) AcceptConsent(ctx context.Context, challenge string, accept *OAuthConsentAccept) (*OAuthConsentResponse, error) {
	return nil, errors.New("consent flow not implemented for embedded provider; use HTTP endpoints")
}

// RejectConsent implements OAuthProvider.
func (p *EmbeddedOAuthProvider) RejectConsent(ctx context.Context, challenge string, reject *OAuthConsentReject) (*OAuthConsentResponse, error) {
	return nil, errors.New("consent flow not implemented for embedded provider; use HTTP endpoints")
}

// GetLoginRequest implements OAuthProvider.
func (p *EmbeddedOAuthProvider) GetLoginRequest(ctx context.Context, challenge string) (*OAuthLoginRequest, error) {
	return nil, errors.New("login flow not implemented for embedded provider; use HTTP endpoints")
}

// AcceptLogin implements OAuthProvider.
func (p *EmbeddedOAuthProvider) AcceptLogin(ctx context.Context, challenge string, accept *OAuthLoginAccept) (*OAuthLoginResponse, error) {
	return nil, errors.New("login flow not implemented for embedded provider; use HTTP endpoints")
}

// RejectLogin implements OAuthProvider.
func (p *EmbeddedOAuthProvider) RejectLogin(ctx context.Context, challenge string, reject *OAuthLoginReject) (*OAuthLoginResponse, error) {
	return nil, errors.New("login flow not implemented for embedded provider; use HTTP endpoints")
}

// Ensure EmbeddedOAuthProvider implements OAuthProvider.
var _ OAuthProvider = (*EmbeddedOAuthProvider)(nil)

// ============================================================================
// OAuth Client Store
// ============================================================================

// EmbeddedOAuthClientStore implements OAuthClientStore using SystemAuth storage.
type EmbeddedOAuthClientStore struct {
	storage Storage
}

// NewEmbeddedOAuthClientStore creates an OAuthClientStore backed by SystemAuth storage.
func NewEmbeddedOAuthClientStore(storage Storage) *EmbeddedOAuthClientStore {
	return &EmbeddedOAuthClientStore{storage: storage}
}

// CreateClient implements OAuthClientStore.
func (s *EmbeddedOAuthClientStore) CreateClient(ctx context.Context, client *OAuthClient) error {
	now := time.Now()

	// Determine client type
	clientType := ClientTypeConfidential
	if client.Public {
		clientType = ClientTypePublic
	}

	// Convert to internal Client type
	internalClient := &Client{
		ID:            client.ClientID,
		Secret:        client.ClientSecret,
		Name:          client.ClientName,
		Type:          clientType,
		RedirectURIs:  client.RedirectURIs,
		GrantTypes:    client.GrantTypes,
		ResponseTypes: client.ResponseTypes,
		Scopes:        strings.Split(client.Scope, " "),
		Audience:      client.Audience,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	// Hash the secret if provided
	if client.ClientSecret != "" {
		hash, err := hashSecret(client.ClientSecret)
		if err != nil {
			return err
		}
		internalClient.SecretHash = hash
	}

	return s.storage.CreateClient(ctx, internalClient)
}

// GetClient implements OAuthClientStore.
func (s *EmbeddedOAuthClientStore) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	client, err := s.storage.GetClientByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	return internalClientToOAuthClient(client), nil
}

// UpdateClient implements OAuthClientStore.
func (s *EmbeddedOAuthClientStore) UpdateClient(ctx context.Context, client *OAuthClient) error {
	// Get existing client to preserve created_at and secret hash
	existing, err := s.storage.GetClientByID(ctx, client.ClientID)
	if err != nil {
		return err
	}

	// Determine client type
	clientType := ClientTypeConfidential
	if client.Public {
		clientType = ClientTypePublic
	}

	internalClient := &Client{
		ID:            client.ClientID,
		SecretHash:    existing.SecretHash, // Preserve existing secret hash
		Name:          client.ClientName,
		Type:          clientType,
		RedirectURIs:  client.RedirectURIs,
		GrantTypes:    client.GrantTypes,
		ResponseTypes: client.ResponseTypes,
		Scopes:        strings.Split(client.Scope, " "),
		Audience:      client.Audience,
		CreatedAt:     existing.CreatedAt,
		UpdatedAt:     time.Now(),
	}

	// Update secret if a new one is provided
	if client.ClientSecret != "" {
		hash, err := hashSecret(client.ClientSecret)
		if err != nil {
			return err
		}
		internalClient.SecretHash = hash
	}

	return s.storage.UpdateClient(ctx, internalClient)
}

// DeleteClient implements OAuthClientStore.
func (s *EmbeddedOAuthClientStore) DeleteClient(ctx context.Context, clientID string) error {
	return s.storage.DeleteClient(ctx, clientID)
}

// ListClients implements OAuthClientStore.
func (s *EmbeddedOAuthClientStore) ListClients(ctx context.Context) ([]*OAuthClient, error) {
	clients, err := s.storage.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	result := make([]*OAuthClient, len(clients))
	for i, c := range clients {
		result[i] = internalClientToOAuthClient(c)
	}

	return result, nil
}

// internalClientToOAuthClient converts internal Client to OAuthClient.
func internalClientToOAuthClient(c *Client) *OAuthClient {
	return &OAuthClient{
		ClientID:      c.ID,
		ClientName:    c.Name,
		RedirectURIs:  c.RedirectURIs,
		GrantTypes:    c.GrantTypes,
		ResponseTypes: c.ResponseTypes,
		Scope:         strings.Join(c.Scopes, " "),
		Audience:      c.Audience,
		Public:        c.Type == ClientTypePublic,
		CreatedAt:     c.CreatedAt,
		UpdatedAt:     c.UpdatedAt,
	}
}

// Ensure EmbeddedOAuthClientStore implements OAuthClientStore.
var _ OAuthClientStore = (*EmbeddedOAuthClientStore)(nil)
