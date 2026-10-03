package systemauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FederationClient connects a SystemAuth app to SystemAuth for SSO.
type FederationClient struct {
	config     *FederationConfig
	httpClient *http.Client
	tokenCache *federationTokenCache
	discovery  *SystemAuthDiscovery
	mu         sync.RWMutex
}

// SystemAuthDiscovery holds the OIDC discovery configuration from SystemAuth.
type SystemAuthDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JwksURI               string   `json:"jwks_uri"`
	IntrospectionEndpoint string   `json:"introspection_endpoint"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// federationTokenCache stores tokens for app-to-SystemAuth communication.
type federationTokenCache struct {
	mu          sync.RWMutex
	accessToken string
	expiresAt   time.Time
}

// GlobalIdentity represents a user's identity from SystemAuth.
type GlobalIdentity struct {
	ID           uuid.UUID              `json:"id"`
	FederationID uuid.UUID              `json:"federation_id"`
	Email        string                 `json:"email"`
	DisplayName  string                 `json:"display_name"`
	Status       string                 `json:"status"`
	Attributes   map[string]interface{} `json:"attributes,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
}

// IdentityMapping maps a global identity to a local principal.
type IdentityMapping struct {
	ID               uuid.UUID `json:"id"`
	GlobalIdentityID uuid.UUID `json:"global_identity_id"`
	AppID            string    `json:"app_id"`
	LocalPrincipalID uuid.UUID `json:"local_principal_id"`
	MappedAt         time.Time `json:"mapped_at"`
	SyncStatus       string    `json:"sync_status"`
}

// SSOSession represents an active SSO session from SystemAuth.
type SSOSession struct {
	ID               uuid.UUID `json:"id"`
	GlobalIdentityID uuid.UUID `json:"global_identity_id"`
	AuthTime         time.Time `json:"auth_time"`
	ExpiresAt        time.Time `json:"expires_at"`
	AppsAccessed     []string  `json:"apps_accessed"`
}

// IdentitySyncRequest is received from SystemAuth to sync an identity.
type IdentitySyncRequest struct {
	Action   string          `json:"action"` // create, update, delete
	Identity *GlobalIdentity `json:"identity"`
}

// IdentitySyncResponse is returned to SystemAuth after syncing.
type IdentitySyncResponse struct {
	LocalPrincipalID uuid.UUID `json:"local_principal_id"`
	Status           string    `json:"status"` // synced, pending, failed
	Error            string    `json:"error,omitempty"`
}

// NewFederationClient creates a new federation client.
func NewFederationClient(config *FederationConfig) (*FederationClient, error) {
	if config == nil || !config.Enabled {
		return nil, fmt.Errorf("federation not enabled")
	}

	if config.SystemAuthURL == "" {
		return nil, fmt.Errorf("systemauth_url is required")
	}

	if config.ClientID == "" || config.ClientSecret == "" {
		return nil, fmt.Errorf("client_id and client_secret are required")
	}

	client := &FederationClient{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		tokenCache: &federationTokenCache{},
	}

	return client, nil
}

// Initialize fetches the SystemAuth discovery document.
func (c *FederationClient) Initialize(ctx context.Context) error {
	discoveryURL := c.config.SystemAuthURL + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := c.httpClient.Do(req) //nolint:gosec // URL is from configured systemauth_url, not user input
	if err != nil {
		return fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}

	var discovery SystemAuthDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return fmt.Errorf("failed to decode discovery document: %w", err)
	}

	c.mu.Lock()
	c.discovery = &discovery
	c.mu.Unlock()

	return nil
}

// getAccessToken obtains or refreshes the app's access token for SystemAuth.
func (c *FederationClient) getAccessToken(ctx context.Context) (string, error) {
	c.tokenCache.mu.RLock()
	if c.tokenCache.accessToken != "" && time.Now().Before(c.tokenCache.expiresAt.Add(-30*time.Second)) {
		token := c.tokenCache.accessToken
		c.tokenCache.mu.RUnlock()
		return token, nil
	}
	c.tokenCache.mu.RUnlock()

	// Need to get a new token
	c.mu.RLock()
	discovery := c.discovery
	c.mu.RUnlock()

	if discovery == nil {
		if err := c.Initialize(ctx); err != nil {
			return "", err
		}
		c.mu.RLock()
		discovery = c.discovery
		c.mu.RUnlock()
	}

	// Use client credentials grant
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)
	data.Set("scope", "federation")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.TokenEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req) //nolint:gosec // URL is from OIDC discovery, not user input
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"` //nolint:gosec // OAuth 2.0 spec field name
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	c.tokenCache.mu.Lock()
	c.tokenCache.accessToken = tokenResp.AccessToken
	c.tokenCache.expiresAt = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	c.tokenCache.mu.Unlock()

	return tokenResp.AccessToken, nil
}

// GetSSOAuthorizationURL generates the URL to redirect users to SystemAuth for SSO.
func (c *FederationClient) GetSSOAuthorizationURL(ctx context.Context, state, redirectURI string) (string, error) {
	c.mu.RLock()
	discovery := c.discovery
	c.mu.RUnlock()

	if discovery == nil {
		if err := c.Initialize(ctx); err != nil {
			return "", err
		}
		c.mu.RLock()
		discovery = c.discovery
		c.mu.RUnlock()
	}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.config.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", "openid profile email")
	params.Set("state", state)

	return discovery.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// ExchangeCode exchanges an authorization code from SystemAuth for tokens.
func (c *FederationClient) ExchangeCode(ctx context.Context, code, redirectURI string) (*SSOTokenResponse, error) {
	c.mu.RLock()
	discovery := c.discovery
	c.mu.RUnlock()

	if discovery == nil {
		return nil, fmt.Errorf("federation client not initialized")
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", c.config.ClientID)
	data.Set("client_secret", c.config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.TokenEndpoint, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req) //nolint:gosec // URL is from OIDC discovery, not user input
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp SSOTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// SSOTokenResponse contains tokens from SystemAuth SSO.
//
//nolint:gosec // G117: Field names are OAuth 2.0 spec-compliant
type SSOTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// GetGlobalIdentity retrieves a global identity from SystemAuth.
func (c *FederationClient) GetGlobalIdentity(ctx context.Context, globalID uuid.UUID) (*GlobalIdentity, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	identityURL := fmt.Sprintf("%s/identities/%s", c.config.SystemAuthURL, globalID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, identityURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req) //nolint:gosec // URL is from configured systemauth_url
	if err != nil {
		return nil, fmt.Errorf("failed to get identity: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get identity failed with status %d", resp.StatusCode)
	}

	var identity GlobalIdentity
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return nil, fmt.Errorf("failed to decode identity: %w", err)
	}

	return &identity, nil
}

// GetIdentityMapping retrieves the mapping for a global identity in this app.
func (c *FederationClient) GetIdentityMapping(ctx context.Context, globalID uuid.UUID) (*IdentityMapping, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	mappingURL := fmt.Sprintf("%s/identities/%s/mappings", c.config.SystemAuthURL, globalID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mappingURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create mapping request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req) //nolint:gosec // URL is from configured systemauth_url
	if err != nil {
		return nil, fmt.Errorf("failed to get mapping: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get mapping failed with status %d", resp.StatusCode)
	}

	var mappings []IdentityMapping
	if err := json.NewDecoder(resp.Body).Decode(&mappings); err != nil {
		return nil, fmt.Errorf("failed to decode mappings: %w", err)
	}

	// Find mapping for this app
	for _, m := range mappings {
		if m.AppID == c.config.AppID {
			return &m, nil
		}
	}

	return nil, fmt.Errorf("no mapping found for app %s", c.config.AppID)
}

// ValidateSSOSession validates an SSO session with SystemAuth.
func (c *FederationClient) ValidateSSOSession(ctx context.Context, sessionID uuid.UUID) (*SSOSession, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	sessionURL := fmt.Sprintf("%s/sso/session", c.config.SystemAuthURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sessionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create session request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-SSO-Session", sessionID.String())

	resp, err := c.httpClient.Do(req) //nolint:gosec // URL is from configured systemauth_url
	if err != nil {
		return nil, fmt.Errorf("failed to validate session: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session validation failed with status %d", resp.StatusCode)
	}

	var session SSOSession
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return nil, fmt.Errorf("failed to decode session: %w", err)
	}

	return &session, nil
}

// NotifyAppAccess records that a user accessed this app via SSO.
func (c *FederationClient) NotifyAppAccess(ctx context.Context, sessionID uuid.UUID) error {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return err
	}

	accessURL := fmt.Sprintf("%s/sso/apps", c.config.SystemAuthURL)

	body := map[string]string{
		"app_id": c.config.AppID,
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, accessURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create access notification request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-SSO-Session", sessionID.String())
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req) //nolint:gosec // URL is from configured systemauth_url
	if err != nil {
		return fmt.Errorf("failed to notify app access: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("access notification failed with status %d", resp.StatusCode)
	}

	return nil
}

// RegisterWithSystemAuth registers this app with a federation.
func (c *FederationClient) RegisterWithSystemAuth(ctx context.Context, federationID uuid.UUID, displayName, baseURL string, capabilities []string) error {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return err
	}

	registerURL := fmt.Sprintf("%s/federations/%s/apps", c.config.SystemAuthURL, federationID)

	body := map[string]interface{}{
		"app_id":           c.config.AppID,
		"display_name":     displayName,
		"base_url":         baseURL,
		"contract_version": "1.0",
		"capabilities":     capabilities,
	}
	bodyBytes, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create registration request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req) //nolint:gosec // URL is from configured systemauth_url
	if err != nil {
		return fmt.Errorf("failed to register app: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Config returns the federation configuration.
func (c *FederationClient) Config() *FederationConfig {
	return c.config
}

// Discovery returns the SystemAuth discovery document.
func (c *FederationClient) Discovery() *SystemAuthDiscovery {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.discovery
}
