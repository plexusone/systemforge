package jwt

import (
	"errors"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var testSecret = []byte("test-secret-key-32-bytes-long!!")

func newValidationService(t *testing.T, issuer string) *Service {
	t.Helper()
	svc, err := NewService(&Config{
		Secret:             testSecret,
		Algorithm:          "HS256",
		Issuer:             issuer,
		Audience:           []string{AudienceBFF},
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func signed(t *testing.T, method gojwt.SigningMethod, key any, claims *Claims) string {
	t.Helper()
	s, err := gojwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func accessClaims(issuer string, audience []string, expiry *time.Time) *Claims {
	c := &Claims{
		PrincipalID: uuid.New(),
		TokenType:   AccessToken,
	}
	c.Issuer = issuer
	c.RegisteredClaims.Audience = audience
	if expiry != nil {
		c.ExpiresAt = gojwt.NewNumericDate(*expiry)
	}
	return c
}

func TestValidationRequiresExpiryAndTheConfiguredIssuer(t *testing.T) {
	svc := newValidationService(t, "https://issuer.example")
	future := time.Now().Add(time.Hour)

	if _, err := svc.ValidateAccessToken(signed(t, gojwt.SigningMethodHS256, testSecret, accessClaims("https://issuer.example", []string{AudienceBFF}, &future))); err != nil {
		t.Fatalf("a good token: %v", err)
	}
	for name, claims := range map[string]*Claims{
		"no expiry":    accessClaims("https://issuer.example", []string{AudienceBFF}, nil),
		"wrong issuer": accessClaims("https://evil.example", []string{AudienceBFF}, &future),
		"no issuer":    accessClaims("", []string{AudienceBFF}, &future),
	} {
		if _, err := svc.ValidateAccessToken(signed(t, gojwt.SigningMethodHS256, testSecret, claims)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A different HMAC algorithm than configured is refused even though it
	// is the same family and key.
	if _, err := svc.ValidateAccessToken(signed(t, gojwt.SigningMethodHS512, testSecret, accessClaims("https://issuer.example", []string{AudienceBFF}, &future))); err == nil {
		t.Error("an HS512 token was accepted by an HS256 service")
	}
	// `none` is never accepted.
	none, err := gojwt.NewWithClaims(gojwt.SigningMethodNone, accessClaims("https://issuer.example", []string{AudienceBFF}, &future)).SignedString(gojwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := svc.ValidateAccessToken(none); err == nil {
		t.Error("an unsigned token was accepted")
	}
	// Issuer checking is opt-in via config, as before.
	open := newValidationService(t, "")
	if _, err := open.ValidateAccessToken(signed(t, gojwt.SigningMethodHS256, testSecret, accessClaims("anyone", []string{AudienceBFF}, &future))); err != nil {
		t.Errorf("no configured issuer: %v", err)
	}
}

func TestValidateAccessTokenForAudience(t *testing.T) {
	svc := newValidationService(t, "")
	future := time.Now().Add(time.Hour)
	api := signed(t, gojwt.SigningMethodHS256, testSecret, accessClaims("", []string{AudienceAPI}, &future))
	bff := signed(t, gojwt.SigningMethodHS256, testSecret, accessClaims("", []string{AudienceBFF}, &future))

	if _, err := svc.ValidateAccessTokenForAudience(bff, AudienceBFF); err != nil {
		t.Errorf("a browser token on a browser route: %v", err)
	}
	if _, err := svc.ValidateAccessTokenForAudience(api, AudienceBFF); !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("an API token on a browser route = %v, want ErrAudienceMismatch", err)
	}
	if _, err := svc.ValidateAccessTokenForAudience(api, AudienceBFF, AudienceAPI); err != nil {
		t.Errorf("a route serving both: %v", err)
	}
	if _, err := svc.ValidateAccessTokenForAudience(api); !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("no audiences accepted anything: %v", err)
	}
}
