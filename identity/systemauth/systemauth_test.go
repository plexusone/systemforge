package systemauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/systemauth"
)

func TestNewEmbedded(t *testing.T) {
	server, err := systemauth.NewEmbedded(systemauth.Config{
		Issuer: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	if server == nil {
		t.Fatal("server is nil")
	}

	if server.Router() == nil {
		t.Fatal("router is nil")
	}
}

func TestOpenIDConfiguration(t *testing.T) {
	server, err := systemauth.NewEmbedded(systemauth.Config{
		Issuer: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// Test discovery endpoint
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var config systemauth.OpenIDConfiguration
	if err := json.NewDecoder(w.Body).Decode(&config); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if config.Issuer != "https://test.example.com" {
		t.Errorf("expected issuer https://test.example.com, got %s", config.Issuer)
	}

	if config.TokenEndpoint != "https://test.example.com/oauth/token" {
		t.Errorf("expected token endpoint https://test.example.com/oauth/token, got %s", config.TokenEndpoint)
	}
}

func TestJWKS(t *testing.T) {
	server, err := systemauth.NewEmbedded(systemauth.Config{
		Issuer: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// Test JWKS endpoint
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var jwks map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	keys, ok := jwks["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Error("expected at least one key in JWKS")
	}
}

func TestClientCredentialsFlow(t *testing.T) {
	server, err := systemauth.NewEmbedded(systemauth.Config{
		Issuer: "https://test.example.com",
		Clients: []systemauth.ClientConfig{
			{
				ID:         "test-client",
				Secret:     "test-secret",
				Type:       "confidential",
				Name:       "Test Client",
				GrantTypes: []string{"client_credentials"},
				Scopes:     []string{"read", "write"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// Test token endpoint with client credentials
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")
	form.Set("scope", "read")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if _, ok := tokenResp["access_token"]; !ok {
		t.Error("expected access_token in response")
	}

	if tokenResp["token_type"] != "bearer" {
		t.Errorf("expected token_type bearer, got %v", tokenResp["token_type"])
	}
}

func TestClientWithCustomScopes(t *testing.T) {
	server, err := systemauth.NewEmbedded(systemauth.Config{
		Issuer: "https://test.example.com",
		Clients: []systemauth.ClientConfig{
			{
				ID:         "api-client",
				Secret:     "api-secret",
				Type:       "confidential",
				Name:       "API Client",
				GrantTypes: []string{"client_credentials"},
				Scopes:     []string{"certificates:read", "certificates:write"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// Verify client was registered
	client, err := server.GetClient("api-client")
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}

	if client.ID != "api-client" {
		t.Errorf("expected client ID api-client, got %s", client.ID)
	}

	scopes := client.GetScopes()
	if len(scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(scopes))
	}
}

func TestInvalidClient(t *testing.T) {
	server, err := systemauth.NewEmbedded(systemauth.Config{
		Issuer: "https://test.example.com",
	})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// Test token endpoint with invalid client
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "nonexistent")
	form.Set("client_secret", "wrong")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	// Should fail with unauthorized
	if w.Code == http.StatusOK {
		t.Fatal("expected error for invalid client, got 200")
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	// Create a session provider that auto-authenticates and auto-consents
	sessionProvider := systemauth.NewDefaultSessionProvider(
		systemauth.WithUserIDHeader("X-Test-User"),
		systemauth.WithSkipConsent(true),
	)

	server, err := systemauth.NewEmbedded(systemauth.Config{
		Issuer: "https://test.example.com",
		Clients: []systemauth.ClientConfig{
			{
				ID:            "spa-client",
				Type:          "public",
				Name:          "SPA Client",
				RedirectURIs:  []string{"https://spa.example.com/callback"},
				GrantTypes:    []string{"authorization_code", "refresh_token"},
				ResponseTypes: []string{"code"},
				Scopes:        []string{"openid", "profile", "email"},
			},
		},
	}, systemauth.WithSessionProvider(sessionProvider))
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// Build auth URL with proper URL encoding
	authParams := url.Values{}
	authParams.Set("response_type", "code")
	authParams.Set("client_id", "spa-client")
	authParams.Set("redirect_uri", "https://spa.example.com/callback")
	authParams.Set("scope", "openid profile")
	authParams.Set("state", "xyz12345678")
	// Valid PKCE code challenge (SHA256 of "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	authParams.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	authParams.Set("code_challenge_method", "S256")

	authURL := "/oauth/authorize?" + authParams.Encode()

	// Step 1: Test authorization endpoint without authentication
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	// Should redirect to login (302 or 303)
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect to login (302/303), got %d: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "/login") {
		t.Errorf("expected redirect to /login, got %s", location)
	}

	// Step 2: Test authorization endpoint with authentication
	req = httptest.NewRequest(http.MethodGet, authURL, nil)
	req.Header.Set("X-Test-User", "user-123")
	w = httptest.NewRecorder()
	server.ServeHTTP(w, req)

	// Should redirect to callback with authorization code (302 or 303)
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect to callback (302/303), got %d: %s", w.Code, w.Body.String())
	}

	location = w.Header().Get("Location")
	if !strings.Contains(location, "spa.example.com/callback") {
		t.Errorf("expected redirect to callback URL, got %s", location)
	}

	// Parse the callback URL to get the authorization code
	callbackURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse callback URL: %v", err)
	}

	code := callbackURL.Query().Get("code")
	if code == "" {
		t.Fatal("expected authorization code in callback URL")
	}

	state := callbackURL.Query().Get("state")
	if state != "xyz12345678" {
		t.Errorf("expected state xyz12345678, got %s", state)
	}

	t.Logf("Authorization code issued: %s...", code[:min(20, len(code))])
}

func TestAuthorizationCodeFlowConsentRequired(t *testing.T) {
	// Create a session provider that requires consent
	sessionProvider := systemauth.NewDefaultSessionProvider(
		systemauth.WithUserIDHeader("X-Test-User"),
		systemauth.WithSkipConsent(false),
		systemauth.WithConsentURL("/custom-consent"),
	)

	server, err := systemauth.NewEmbedded(systemauth.Config{
		Issuer: "https://test.example.com",
		Clients: []systemauth.ClientConfig{
			{
				ID:            "web-client",
				Type:          "public",
				Name:          "Web Client",
				RedirectURIs:  []string{"https://web.example.com/callback"},
				GrantTypes:    []string{"authorization_code"},
				ResponseTypes: []string{"code"},
				Scopes:        []string{"openid", "profile"},
			},
		},
	}, systemauth.WithSessionProvider(sessionProvider))
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// Build auth URL with proper URL encoding
	authParams := url.Values{}
	authParams.Set("response_type", "code")
	authParams.Set("client_id", "web-client")
	authParams.Set("redirect_uri", "https://web.example.com/callback")
	authParams.Set("scope", "openid")
	authParams.Set("state", "abcdefgh")
	authParams.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	authParams.Set("code_challenge_method", "S256")

	authURL := "/oauth/authorize?" + authParams.Encode()
	req := httptest.NewRequest(http.MethodGet, authURL, nil)
	req.Header.Set("X-Test-User", "user-456")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	// Should redirect to consent (302 or 303)
	if w.Code != http.StatusFound && w.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect (302/303), got %d: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if !strings.Contains(location, "/custom-consent") {
		t.Errorf("expected redirect to /custom-consent, got %s", location)
	}
}

func TestMiddleware(t *testing.T) {
	server, err := systemauth.NewEmbedded(systemauth.Config{
		Issuer: "https://test.example.com",
		Clients: []systemauth.ClientConfig{
			{
				ID:         "test-client",
				Secret:     "test-secret",
				Type:       "confidential",
				Name:       "Test Client",
				GrantTypes: []string{"client_credentials"},
				Scopes:     []string{"read"},
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEmbedded failed: %v", err)
	}

	// First, get a token
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "test-client")
	form.Set("client_secret", "test-secret")
	form.Set("scope", "read")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	server.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("token request failed: %d: %s", w.Code, w.Body.String())
	}

	var tokenResp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok {
		t.Fatal("access_token not found in response")
	}

	// Test middleware with valid token
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ar := systemauth.AccessRequestFromContext(r.Context())
		if ar == nil {
			t.Error("expected access request in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	middleware := server.Middleware()
	handler := middleware(protectedHandler)

	req = httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Test middleware without token
	req = httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
