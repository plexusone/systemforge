package jwt

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNewService(t *testing.T) {
	// Test with nil config
	_, err := NewService(nil)
	if err == nil {
		t.Error("expected error with nil config (no signing key)")
	}

	// Test with valid secret
	cfg := &Config{
		Secret:            []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:         "HS256",
		Audience:          []string{"test-app"},
		Issuer:            "test-issuer",
		AccessTokenExpiry: 15 * time.Minute,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Errorf("NewService failed: %v", err)
	}
	if svc == nil {
		t.Error("expected non-nil service")
	}
}

func TestGenerateAndValidateAccessToken(t *testing.T) {
	cfg := &Config{
		Secret:            []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:         "HS256",
		Audience:          []string{"test-app"},
		Issuer:            "test-issuer",
		AccessTokenExpiry: 15 * time.Minute,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	principalID := uuid.New()
	email := "test@example.com"
	name := "Test User"

	token, err := svc.GenerateAccessToken(principalID, email, name)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}
	if token == "" {
		t.Error("expected non-empty token")
	}

	claims, err := svc.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	if claims.PrincipalID != principalID {
		t.Errorf("expected principalID %s, got %s", principalID, claims.PrincipalID)
	}
	if claims.Email != email {
		t.Errorf("expected email %s, got %s", email, claims.Email)
	}
	if claims.Name != name {
		t.Errorf("expected name %s, got %s", name, claims.Name)
	}
	if !claims.IsAccessToken() {
		t.Error("expected access token type")
	}
}

func TestGenerateAndValidateRefreshToken(t *testing.T) {
	cfg := &Config{
		Secret:             []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:          "HS256",
		Audience:           []string{"test-app"},
		Issuer:             "test-issuer",
		RefreshTokenExpiry: 7 * 24 * time.Hour,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	principalID := uuid.New()
	family := uuid.NewString()

	token, err := svc.GenerateRefreshToken(principalID, family)
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	claims, err := svc.ValidateRefreshToken(token)
	if err != nil {
		t.Fatalf("ValidateRefreshToken failed: %v", err)
	}

	if claims.PrincipalID != principalID {
		t.Errorf("expected principalID %s, got %s", principalID, claims.PrincipalID)
	}
	if claims.TokenFamily != family {
		t.Errorf("expected family %s, got %s", family, claims.TokenFamily)
	}
	if !claims.IsRefreshToken() {
		t.Error("expected refresh token type")
	}
}

func TestWrongTokenType(t *testing.T) {
	cfg := &Config{
		Secret:             []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:          "HS256",
		Audience:           []string{"test-app"},
		Issuer:             "test-issuer",
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	principalID := uuid.New()

	// Generate refresh token
	refreshToken, err := svc.GenerateRefreshToken(principalID, "")
	if err != nil {
		t.Fatalf("GenerateRefreshToken failed: %v", err)
	}

	// Try to validate as access token
	_, err = svc.ValidateAccessToken(refreshToken)
	if err != ErrWrongTokenType {
		t.Errorf("expected ErrWrongTokenType, got %v", err)
	}

	// Generate access token
	accessToken, err := svc.GenerateAccessToken(principalID, "test@example.com", "Test")
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Try to validate as refresh token
	_, err = svc.ValidateRefreshToken(accessToken)
	if err != ErrWrongTokenType {
		t.Errorf("expected ErrWrongTokenType, got %v", err)
	}
}

func TestTokenPair(t *testing.T) {
	cfg := &Config{
		Secret:             []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:          "HS256",
		Audience:           []string{"test-app"},
		Issuer:             "test-issuer",
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	principalID := uuid.New()
	pair, err := svc.GenerateTokenPair(principalID, "test@example.com", "Test User")
	if err != nil {
		t.Fatalf("GenerateTokenPair failed: %v", err)
	}

	if pair.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	if pair.RefreshToken == "" {
		t.Error("expected non-empty refresh token")
	}
	if pair.ExpiresIn != int64(cfg.AccessTokenExpiry.Seconds()) {
		t.Errorf("expected expires_in %d, got %d", int64(cfg.AccessTokenExpiry.Seconds()), pair.ExpiresIn)
	}
}

func TestOrganizationContext(t *testing.T) {
	cfg := &Config{
		Secret:            []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:         "HS256",
		Audience:          []string{"test-app"},
		Issuer:            "test-issuer",
		AccessTokenExpiry: 15 * time.Minute,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	principalID := uuid.New()
	orgID := uuid.New()
	permissions := []string{"read", "write"}

	token, err := svc.GenerateAccessTokenWithOrg(
		principalID, "test@example.com", "Test User",
		orgID, "test-org", "admin", permissions, true,
	)
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithOrg failed: %v", err)
	}

	claims, err := svc.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	if claims.OrganizationID == nil || *claims.OrganizationID != orgID {
		t.Errorf("expected orgID %s, got %v", orgID, claims.OrganizationID)
	}
	if claims.OrganizationSlug != "test-org" {
		t.Errorf("expected slug test-org, got %s", claims.OrganizationSlug)
	}
	if claims.Role != "admin" {
		t.Errorf("expected role admin, got %s", claims.Role)
	}
	if len(claims.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(claims.Permissions))
	}
	if !claims.IsPlatformAdmin {
		t.Error("expected IsPlatformAdmin to be true")
	}
}

func TestInvalidToken(t *testing.T) {
	cfg := &Config{
		Secret:            []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:         "HS256",
		Audience:          []string{"test-app"},
		Issuer:            "test-issuer",
		AccessTokenExpiry: 15 * time.Minute,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	_, err = svc.ValidateAccessToken("invalid-token")
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestGenerateAccessTokenWithOptions_DPoP(t *testing.T) {
	cfg := &Config{
		Secret:            []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:         "HS256",
		Audience:          []string{"test-app"},
		Issuer:            "test-issuer",
		AccessTokenExpiry: 15 * time.Minute,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	principalID := uuid.New()
	thumbprint := "example-dpop-thumbprint"

	token, err := svc.GenerateAccessTokenWithOptions(principalID, "test@example.com", "Test User", TokenOptions{
		DPoPThumbprint: thumbprint,
	})
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithOptions failed: %v", err)
	}

	claims, err := svc.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	if !claims.IsDPoPBound() {
		t.Error("expected token to be DPoP-bound")
	}
	if claims.DPoPThumbprint() != thumbprint {
		t.Errorf("expected thumbprint %s, got %s", thumbprint, claims.DPoPThumbprint())
	}
}

func TestGenerateAccessTokenWithOrgAndOptions_DPoP(t *testing.T) {
	cfg := &Config{
		Secret:            []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:         "HS256",
		Audience:          []string{"test-app"},
		Issuer:            "test-issuer",
		AccessTokenExpiry: 15 * time.Minute,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	principalID := uuid.New()
	orgID := uuid.New()
	thumbprint := "org-dpop-thumbprint"

	token, err := svc.GenerateAccessTokenWithOrgAndOptions(
		principalID, "test@example.com", "Test User",
		orgID, "test-org", "admin", []string{"read"}, false,
		TokenOptions{DPoPThumbprint: thumbprint},
	)
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithOrgAndOptions failed: %v", err)
	}

	claims, err := svc.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	// Verify DPoP binding
	if !claims.IsDPoPBound() {
		t.Error("expected token to be DPoP-bound")
	}
	if claims.DPoPThumbprint() != thumbprint {
		t.Errorf("expected thumbprint %s, got %s", thumbprint, claims.DPoPThumbprint())
	}

	// Verify organization context
	if claims.OrganizationID == nil || *claims.OrganizationID != orgID {
		t.Errorf("expected orgID %s, got %v", orgID, claims.OrganizationID)
	}
	if claims.Role != "admin" {
		t.Errorf("expected role admin, got %s", claims.Role)
	}
}

func TestGenerateTokenPairWithOptions_DPoP(t *testing.T) {
	cfg := &Config{
		Secret:             []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:          "HS256",
		Audience:           []string{"test-app"},
		Issuer:             "test-issuer",
		AccessTokenExpiry:  15 * time.Minute,
		RefreshTokenExpiry: 7 * 24 * time.Hour,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	principalID := uuid.New()
	thumbprint := "pair-dpop-thumbprint"

	pair, err := svc.GenerateTokenPairWithOptions(principalID, "test@example.com", "Test User", TokenOptions{
		DPoPThumbprint: thumbprint,
	})
	if err != nil {
		t.Fatalf("GenerateTokenPairWithOptions failed: %v", err)
	}

	// Verify access token is DPoP-bound
	claims, err := svc.ValidateAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	if !claims.IsDPoPBound() {
		t.Error("expected access token to be DPoP-bound")
	}
	if claims.DPoPThumbprint() != thumbprint {
		t.Errorf("expected thumbprint %s, got %s", thumbprint, claims.DPoPThumbprint())
	}

	// Verify refresh token is NOT DPoP-bound (refresh tokens don't need DPoP)
	refreshClaims, err := svc.ValidateRefreshToken(pair.RefreshToken)
	if err != nil {
		t.Fatalf("ValidateRefreshToken failed: %v", err)
	}

	if refreshClaims.IsDPoPBound() {
		t.Error("expected refresh token to NOT be DPoP-bound")
	}
}

func TestGenerateAccessTokenWithOptions_NoDPoP(t *testing.T) {
	cfg := &Config{
		Secret:            []byte("test-secret-key-at-least-32-bytes-long"),
		Algorithm:         "HS256",
		Audience:          []string{"test-app"},
		Issuer:            "test-issuer",
		AccessTokenExpiry: 15 * time.Minute,
	}
	svc, err := NewService(cfg)
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	principalID := uuid.New()

	// Empty options should not bind DPoP
	token, err := svc.GenerateAccessTokenWithOptions(principalID, "test@example.com", "Test User", TokenOptions{})
	if err != nil {
		t.Fatalf("GenerateAccessTokenWithOptions failed: %v", err)
	}

	claims, err := svc.ValidateAccessToken(token)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	if claims.IsDPoPBound() {
		t.Error("expected token to NOT be DPoP-bound with empty options")
	}
}
