package contract

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTokenTestAPI(t *testing.T, key *rsa.PrivateKey, issuer string) *API {
	t.Helper()
	provider, err := NewProvider(&Config{
		AppID:               "test-app",
		DisplayName:         "Test",
		Version:             "1",
		BaseURL:             "/systemforge",
		SystemAuthIssuer:    issuer,
		SystemAuthPublicKey: &key.PublicKey,
	}, nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	api, err := NewAPI(provider)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	return api
}

func signRS256(t *testing.T, key *rsa.PrivateKey, claims SystemAuthClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// TestValidateTokenRequiresExpiryAndAudience verifies that a SystemAuth
// token must expire and must be addressed to this application.
func TestValidateTokenRequiresExpiryAndAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	api := newTokenTestAPI(t, key, "https://auth.example.com")
	future := jwt.NewNumericDate(time.Now().Add(time.Hour))
	claims := func(mod func(*SystemAuthClaims)) SystemAuthClaims {
		c := SystemAuthClaims{RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "https://auth.example.com", Subject: "kim", Audience: jwt.ClaimStrings{"test-app"}, ExpiresAt: future,
		}}
		mod(&c)
		return c
	}

	if _, err := api.validateToken(signRS256(t, key, claims(func(*SystemAuthClaims) {}))); err != nil {
		t.Fatalf("a good token: %v", err)
	}
	for name, mod := range map[string]func(*SystemAuthClaims){
		"no expiry":      func(c *SystemAuthClaims) { c.ExpiresAt = nil },
		"expired":        func(c *SystemAuthClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute)) },
		"other audience": func(c *SystemAuthClaims) { c.Audience = jwt.ClaimStrings{"another-app"} },
		"no audience":    func(c *SystemAuthClaims) { c.Audience = nil },
		"other issuer":   func(c *SystemAuthClaims) { c.Issuer = "https://evil.example" },
	} {
		if _, err := api.validateToken(signRS256(t, key, claims(mod))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A token signed by another key is refused.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := api.validateToken(signRS256(t, other, claims(func(*SystemAuthClaims) {}))); err == nil {
		t.Error("a token signed by another key was accepted")
	}
}
