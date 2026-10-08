package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ory/fosite"
)

// TestOpenIDConfiguration tests the OpenID Connect discovery endpoint.
func TestOpenIDConfiguration(t *testing.T) {
	issuer := "https://auth.example.com"
	config := &Config{
		Issuer:               issuer,
		AccessTokenLifespan:  15 * time.Minute,
		RefreshTokenLifespan: 7 * 24 * time.Hour,
		AuthCodeLifespan:     10 * time.Minute,
		HashSecret:           []byte("test-secret-32-bytes-long-xxxxx"),
	}

	// Create a minimal provider (without Ent database)
	provider := &Provider{
		config: config,
	}

	api := &API{
		provider: provider,
	}

	// Call the handler directly
	output, err := api.getOpenIDConfiguration(context.Background(), &struct{}{})
	if err != nil {
		t.Fatalf("getOpenIDConfiguration returned error: %v", err)
	}

	oidc := output.Body

	// Verify issuer
	if oidc.Issuer != issuer {
		t.Errorf("expected issuer %q, got %q", issuer, oidc.Issuer)
	}

	// Verify endpoints
	expectedAuthEndpoint := issuer + "/oauth/authorize"
	if oidc.AuthorizationEndpoint != expectedAuthEndpoint {
		t.Errorf("expected authorization_endpoint %q, got %q", expectedAuthEndpoint, oidc.AuthorizationEndpoint)
	}

	expectedTokenEndpoint := issuer + "/oauth/token"
	if oidc.TokenEndpoint != expectedTokenEndpoint {
		t.Errorf("expected token_endpoint %q, got %q", expectedTokenEndpoint, oidc.TokenEndpoint)
	}

	expectedIntrospectionEndpoint := issuer + "/oauth/introspect"
	if oidc.IntrospectionEndpoint != expectedIntrospectionEndpoint {
		t.Errorf("expected introspection_endpoint %q, got %q", expectedIntrospectionEndpoint, oidc.IntrospectionEndpoint)
	}

	expectedRevocationEndpoint := issuer + "/oauth/revoke"
	if oidc.RevocationEndpoint != expectedRevocationEndpoint {
		t.Errorf("expected revocation_endpoint %q, got %q", expectedRevocationEndpoint, oidc.RevocationEndpoint)
	}

	expectedJWKSURI := issuer + "/.well-known/jwks.json"
	if oidc.JWKSURI != expectedJWKSURI {
		t.Errorf("expected jwks_uri %q, got %q", expectedJWKSURI, oidc.JWKSURI)
	}

	// Verify response types supported
	if len(oidc.ResponseTypesSupported) != 2 {
		t.Errorf("expected 2 response types, got %d", len(oidc.ResponseTypesSupported))
	}

	// Verify grant types supported
	if len(oidc.GrantTypesSupported) != 3 {
		t.Errorf("expected 3 grant types, got %d", len(oidc.GrantTypesSupported))
	}

	// Verify PKCE support
	if len(oidc.CodeChallengeMethodsSupported) != 1 || oidc.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("expected code_challenge_methods_supported [S256], got %v", oidc.CodeChallengeMethodsSupported)
	}
}

// TestJWKS tests the JSON Web Key Set endpoint.
func TestJWKS(t *testing.T) {
	config := &Config{
		Issuer:     "https://auth.example.com",
		HashSecret: []byte("test-secret-32-bytes-long-xxxxx"),
	}

	provider := &Provider{
		config: config,
	}

	api := &API{
		provider: provider,
	}

	// Call the handler directly
	output, err := api.getJWKS(context.Background(), &struct{}{})
	if err != nil {
		t.Fatalf("getJWKS returned error: %v", err)
	}

	jwks := output.Body

	// Currently returns empty JWKS
	if jwks.Keys == nil {
		t.Error("expected Keys to be non-nil (empty slice)")
	}
}

// TestOpenIDConfigurationHTTP tests the discovery endpoint via HTTP.
func TestOpenIDConfigurationHTTP(t *testing.T) {
	issuer := "https://auth.example.com"
	config := &Config{
		Issuer:               issuer,
		AccessTokenLifespan:  15 * time.Minute,
		RefreshTokenLifespan: 7 * 24 * time.Hour,
		AuthCodeLifespan:     10 * time.Minute,
		HashSecret:           []byte("test-secret-32-bytes-long-xxxxx"),
	}

	provider := &Provider{
		config: config,
	}

	api := &API{
		provider: provider,
	}

	// Create a test server using the handler directly
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		output, err := api.getOpenIDConfiguration(r.Context(), &struct{}{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(output.Body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	//nolint:gosec // test code using test server URL
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("failed to get discovery document: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	var oidc OpenIDConfiguration
	if err := json.Unmarshal(body, &oidc); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if oidc.Issuer != issuer {
		t.Errorf("expected issuer %q, got %q", issuer, oidc.Issuer)
	}
}

// TestJWKSHTTP tests the JWKS endpoint via HTTP.
func TestJWKSHTTP(t *testing.T) {
	config := &Config{
		Issuer:     "https://auth.example.com",
		HashSecret: []byte("test-secret-32-bytes-long-xxxxx"),
	}

	provider := &Provider{
		config: config,
	}

	api := &API{
		provider: provider,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		output, err := api.getJWKS(r.Context(), &struct{}{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(output.Body); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	ts := httptest.NewServer(handler)
	defer ts.Close()

	//nolint:gosec // test code using test server URL
	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("failed to get JWKS: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	var jwks JWKS
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
}

// TestDefaultConfig tests the default configuration helper.
func TestDefaultConfig(t *testing.T) {
	issuer := "https://auth.example.com"
	secret := []byte("my-secret-key")

	config := DefaultConfig(issuer, secret)

	if config.Issuer != issuer {
		t.Errorf("expected issuer %q, got %q", issuer, config.Issuer)
	}

	if config.AccessTokenLifespan != 15*time.Minute {
		t.Errorf("expected access token lifespan 15m, got %v", config.AccessTokenLifespan)
	}

	if config.RefreshTokenLifespan != 7*24*time.Hour {
		t.Errorf("expected refresh token lifespan 7d, got %v", config.RefreshTokenLifespan)
	}

	if config.AuthCodeLifespan != 10*time.Minute {
		t.Errorf("expected auth code lifespan 10m, got %v", config.AuthCodeLifespan)
	}

	if string(config.HashSecret) != string(secret) {
		t.Error("hash secret mismatch")
	}
}

// TestLoggerFromContext tests the context logger helper.
func TestLoggerFromContext(t *testing.T) {
	// Test with no logger in context
	ctx := context.Background()
	logger := LoggerFromContext(ctx)
	if logger == nil {
		t.Error("expected non-nil logger from empty context")
	}

	// Test with logger in context
	customLogger := logger.With("test", "value")
	ctx = withLogger(ctx, customLogger)
	retrieved := LoggerFromContext(ctx)
	if retrieved != customLogger {
		t.Error("expected to retrieve the same logger from context")
	}
}

// TestMiddlewareMissingToken tests the middleware with no token.
func TestMiddlewareMissingToken(t *testing.T) {
	config := &Config{
		Issuer:     "https://auth.example.com",
		HashSecret: []byte("test-secret-32-bytes-long-xxxxx"),
	}

	provider := &Provider{
		config: config,
	}

	api := &API{
		provider: provider,
	}

	// Create a handler that should not be called
	handlerCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with middleware
	handler := api.Middleware(nextHandler)

	// Create request without token
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	if handlerCalled {
		t.Error("expected next handler not to be called when token is missing")
	}
}

// TestTokenTypes tests the OAuth token type constants.
func TestTokenTypes(t *testing.T) {
	// Verify TokenInput fields have correct tags
	input := TokenInput{
		GrantType:    "authorization_code",
		Code:         "test-code",
		RedirectURI:  "https://example.com/callback",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RefreshToken: "test-refresh",
		Scope:        "openid profile",
		CodeVerifier: "test-verifier",
	}

	// Just verify the struct can be created and has expected values
	if input.GrantType != "authorization_code" {
		t.Errorf("expected grant_type authorization_code, got %s", input.GrantType)
	}
}

// TestIntrospectResponse tests introspection response structure.
func TestIntrospectResponse(t *testing.T) {
	resp := IntrospectResponse{
		Active:    true,
		Scope:     "openid profile",
		ClientID:  "test-client",
		Username:  "testuser",
		TokenType: "Bearer",
		Exp:       time.Now().Add(time.Hour).Unix(),
		Iat:       time.Now().Unix(),
		Sub:       "user-123",
		Iss:       "https://auth.example.com",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal introspection response: %v", err)
	}

	var decoded IntrospectResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal introspection response: %v", err)
	}

	if !decoded.Active {
		t.Error("expected active to be true")
	}

	if decoded.ClientID != "test-client" {
		t.Errorf("expected client_id test-client, got %s", decoded.ClientID)
	}
}

// TestOAuthError tests error response structure.
func TestOAuthError(t *testing.T) {
	oauthErr := OAuthError{
		Error:            "invalid_request",
		ErrorDescription: "The request is missing a required parameter",
		ErrorURI:         "https://example.com/error",
	}

	data, err := json.Marshal(oauthErr)
	if err != nil {
		t.Fatalf("failed to marshal OAuth error: %v", err)
	}

	var decoded OAuthError
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal OAuth error: %v", err)
	}

	if decoded.Error != "invalid_request" {
		t.Errorf("expected error invalid_request, got %s", decoded.Error)
	}
}

// TestTokenResponse tests token response structure.
func TestTokenResponse(t *testing.T) {
	resp := TokenResponse{
		AccessToken:  "access-token-123",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh-token-456",
		Scope:        "openid profile",
	}

	data, err := json.Marshal(resp) //nolint:gosec // G117: Testing OAuth token serialization
	if err != nil {
		t.Fatalf("failed to marshal token response: %v", err)
	}

	var decoded TokenResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal token response: %v", err)
	}

	if decoded.TokenType != "Bearer" {
		t.Errorf("expected token_type Bearer, got %s", decoded.TokenType)
	}

	if decoded.ExpiresIn != 3600 {
		t.Errorf("expected expires_in 3600, got %d", decoded.ExpiresIn)
	}
}

// TestFositeInterceptor tests the Fosite path interceptor.
func TestFositeInterceptor(t *testing.T) {
	config := &Config{
		Issuer:     "https://auth.example.com",
		HashSecret: []byte("test-secret-32-bytes-long-xxxxx"),
	}

	provider := &Provider{
		config: config,
	}

	api := &API{
		provider: provider,
	}

	// Track which handler was called
	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	interceptor := api.fositeInterceptor(nextHandler)

	// Test that non-OAuth paths pass through
	tests := []struct {
		path       string
		method     string
		shouldPass bool
	}{
		{"/api/users", http.MethodGet, true},
		{"/.well-known/openid-configuration", http.MethodGet, true},
		{"/health", http.MethodGet, true},
	}

	for _, tc := range tests {
		nextCalled = false
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rec := httptest.NewRecorder()

		interceptor.ServeHTTP(rec, req)

		if tc.shouldPass && !nextCalled {
			t.Errorf("path %s should have passed to next handler", tc.path)
		}
	}
}

// TestHashToken tests token hashing.
func TestHashToken(t *testing.T) {
	token := "test-token-123"
	hash1 := hashToken(token)
	hash2 := hashToken(token)

	// Same token should produce same hash
	if hash1 != hash2 {
		t.Error("expected same hash for same token")
	}

	// Different tokens should produce different hashes
	hash3 := hashToken("different-token")
	if hash1 == hash3 {
		t.Error("expected different hash for different token")
	}

	// Hash should be hex-encoded (64 chars for SHA256)
	if len(hash1) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash1))
	}
}

// TestScopesToStrings tests scope conversion.
func TestScopesToStrings(t *testing.T) {
	scopes := fosite.Arguments{"openid", "profile", "email"}
	result := scopesToStrings(scopes)

	if len(result) != 3 {
		t.Errorf("expected 3 scopes, got %d", len(result))
	}

	for i, scope := range scopes {
		if result[i] != scope {
			t.Errorf("expected scope %q at index %d, got %q", scope, i, result[i])
		}
	}

	// Verify it's a copy, not the same slice
	result[0] = "modified"
	if scopes[0] == "modified" {
		t.Error("modifying result should not affect original")
	}
}

// TestWithAccessRequest tests access request context handling.
func TestWithAccessRequest(t *testing.T) {
	ctx := context.Background()

	// Create a mock access requester
	ar := fosite.NewAccessRequest(nil)

	// Add to context
	ctx = WithAccessRequest(ctx, ar)

	// Retrieve from context
	retrieved := AccessRequestFromContext(ctx)
	if retrieved != ar {
		t.Error("expected to retrieve same access request from context")
	}

	// Test with empty context
	emptyCtx := context.Background()
	nilRequest := AccessRequestFromContext(emptyCtx)
	if nilRequest != nil {
		t.Error("expected nil from empty context")
	}
}

// TestUserIDFromContext tests user ID extraction from access request context.
func TestUserIDFromContext(t *testing.T) {
	// Test with no access request
	ctx := context.Background()
	userID := UserIDFromContext(ctx)
	if userID != "" {
		t.Errorf("expected empty user ID from empty context, got %q", userID)
	}

	// Test with access request but no session
	ar := fosite.NewAccessRequest(nil)
	ctx = WithAccessRequest(ctx, ar)
	userID = UserIDFromContext(ctx)
	if userID != "" {
		t.Errorf("expected empty user ID with nil session, got %q", userID)
	}
}

// TestScopesFromContext tests scope extraction from access request context.
func TestScopesFromContext(t *testing.T) {
	// Test with no access request
	ctx := context.Background()
	scopes := ScopesFromContext(ctx)
	if scopes != nil {
		t.Errorf("expected nil scopes from empty context, got %v", scopes)
	}

	// Test with access request having granted scopes
	ar := fosite.NewAccessRequest(nil)
	ar.GrantScope("openid")
	ar.GrantScope("profile")

	ctx = WithAccessRequest(context.Background(), ar)
	scopes = ScopesFromContext(ctx)
	if len(scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(scopes))
	}
}

// TestHasScope tests scope checking from access request context.
func TestHasScope(t *testing.T) {
	// Test with no access request
	ctx := context.Background()
	if HasScope(ctx, "openid") {
		t.Error("expected HasScope to return false for empty context")
	}

	// Test with access request having granted scopes
	ar := fosite.NewAccessRequest(nil)
	ar.GrantScope("openid")
	ar.GrantScope("profile")

	ctx = WithAccessRequest(context.Background(), ar)

	if !HasScope(ctx, "openid") {
		t.Error("expected HasScope to return true for granted scope")
	}
	if !HasScope(ctx, "profile") {
		t.Error("expected HasScope to return true for granted scope")
	}
	if HasScope(ctx, "email") {
		t.Error("expected HasScope to return false for non-granted scope")
	}
}
