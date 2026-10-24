package jwt

import (
	"bytes"
	"errors"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func keyConfig(secret []byte, kid string, verify map[string]any) *Config {
	return &Config{
		Secret:             secret,
		Algorithm:          "HS256",
		Issuer:             "https://auth.example.com",
		Audience:           []string{"app"},
		KeyID:              kid,
		VerificationKeys:   verify,
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	}
}

func TestConfigRejectsWeakSecretAndMissingIssuer(t *testing.T) {
	short := keyConfig([]byte("too-short"), "", nil)
	if err := short.Validate(); !errors.Is(err, ErrWeakSecret) {
		t.Errorf("short secret: err = %v, want ErrWeakSecret", err)
	}

	hs512 := keyConfig(bytes.Repeat([]byte{1}, 32), "", nil)
	hs512.Algorithm = "HS512"
	if err := hs512.Validate(); !errors.Is(err, ErrWeakSecret) {
		t.Errorf("32-byte HS512 secret: err = %v, want ErrWeakSecret", err)
	}

	noIssuer := keyConfig(bytes.Repeat([]byte{1}, 32), "", nil)
	noIssuer.Issuer = ""
	if err := noIssuer.Validate(); !errors.Is(err, ErrMissingIssuer) {
		t.Errorf("no issuer: err = %v, want ErrMissingIssuer", err)
	}

	weakOld := keyConfig(bytes.Repeat([]byte{1}, 32), "k2", map[string]any{"k1": []byte("short")})
	if err := weakOld.Validate(); !errors.Is(err, ErrInvalidVerificationKey) {
		t.Errorf("weak verification key: err = %v, want ErrInvalidVerificationKey", err)
	}
}

func TestKeyRotation(t *testing.T) {
	oldKey := bytes.Repeat([]byte{1}, 32)
	newKey := bytes.Repeat([]byte{2}, 32)

	oldSvc, err := NewService(keyConfig(oldKey, "k1", nil))
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := oldSvc.GenerateAccessToken(uuid.New(), "a@example.com", "A")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := gojwt.NewParser().ParseUnverified(oldToken, &Claims{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header["kid"] != "k1" {
		t.Fatalf("kid header = %v, want k1", parsed.Header["kid"])
	}

	rotated, err := NewService(keyConfig(newKey, "k2", map[string]any{"k1": oldKey}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.ValidateAccessToken(oldToken); err != nil {
		t.Errorf("token signed with the retiring key rejected: %v", err)
	}
	newToken, err := rotated.GenerateAccessToken(uuid.New(), "b@example.com", "B")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.ValidateAccessToken(newToken); err != nil {
		t.Errorf("token signed with the new key rejected: %v", err)
	}

	retired, err := NewService(keyConfig(newKey, "k2", nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retired.ValidateAccessToken(oldToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("token with a removed kid: err = %v, want ErrInvalidToken", err)
	}
}

// A token whose kid names no configured key must not fall back to the
// signing key.
func TestUnknownKidRejected(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	svc, err := NewService(keyConfig(key, "k1", nil))
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	claims := accessClaims("https://auth.example.com", []string{"app"}, &future)
	tok := gojwt.NewWithClaims(gojwt.SigningMethodHS256, claims)
	tok.Header["kid"] = "other"
	signedTok, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ValidateAccessToken(signedTok); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("unknown kid: err = %v, want ErrInvalidToken", err)
	}
}
