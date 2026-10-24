package jwt

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newAppService(t *testing.T, audience ...string) *Service {
	t.Helper()
	svc, err := NewService(&Config{
		Secret:             testSecret,
		Algorithm:          "HS256",
		Issuer:             "https://auth.example.com",
		Audience:           audience,
		AccessTokenExpiry:  time.Minute,
		RefreshTokenExpiry: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc
}

func TestNewServiceRequiresAudience(t *testing.T) {
	for name, aud := range map[string][]string{"nil": nil, "empty value": {""}} {
		_, err := NewService(&Config{Secret: testSecret, Algorithm: "HS256", Audience: aud})
		if !errors.Is(err, ErrMissingAudience) {
			t.Errorf("%s: err = %v, want ErrMissingAudience", name, err)
		}
	}
}

// Two applications that share a signing key and issuer must not accept
// each other's tokens.
func TestSharedKeyTokensStayInTheirApplication(t *testing.T) {
	appA := newAppService(t, "app-a")
	appB := newAppService(t, "app-b")
	pid := uuid.New()

	access, err := appA.GenerateAccessToken(pid, "kim@example.com", "Kim")
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if _, err := appA.ValidateAccessToken(access); err != nil {
		t.Errorf("app A refused its own token: %v", err)
	}
	if _, err := appB.ValidateAccessToken(access); !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("app B accepted app A's access token: err = %v", err)
	}
	if _, err := appB.ValidateAccessTokenWithAudience(access, ""); !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("ValidateAccessTokenWithAudience(\"\") skipped the audience: err = %v", err)
	}

	pair, err := appA.GenerateTokenPair(pid, "kim@example.com", "Kim")
	if err != nil {
		t.Fatalf("GenerateTokenPair: %v", err)
	}
	if _, err := appB.ValidateRefreshToken(pair.RefreshToken); !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("app B accepted app A's refresh token: err = %v", err)
	}
	if _, err := appA.ValidateRefreshToken(pair.RefreshToken); err != nil {
		t.Errorf("app A refused its own refresh token: %v", err)
	}
}

// Kind audiences (bff, api) are added to the application audience, so kind
// checks and application checks both pass.
func TestKindTokensKeepApplicationAudience(t *testing.T) {
	svc := newAppService(t, "app-a")
	other := newAppService(t, "app-b")
	pid := uuid.New()

	bff, err := svc.GenerateBFFTokenPair(pid, "kim@example.com", "Kim")
	if err != nil {
		t.Fatalf("GenerateBFFTokenPair: %v", err)
	}
	claims, err := svc.ValidateAccessToken(bff.AccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken(bff): %v", err)
	}
	if claims.Audience() != AudienceBFF || !claims.HasAudience("app-a") {
		t.Errorf("bff audience = %v, want [bff app-a]", claims.RegisteredClaims.Audience)
	}
	if _, err := svc.ValidateAccessTokenForAudience(bff.AccessToken, AudienceBFF); err != nil {
		t.Errorf("ValidateAccessTokenForAudience(bff): %v", err)
	}

	api, err := svc.GenerateAPIToken(pid, "kim@example.com", "Kim", []string{"read"}, 0)
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}
	if _, err := svc.ValidateAccessTokenForAudience(api, AudienceBFF); !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("API token accepted as a BFF session: err = %v", err)
	}
	if _, err := other.ValidateAccessToken(api); !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("other application accepted the API token: err = %v", err)
	}
}

func TestValidateForNoAudiencesRefuses(t *testing.T) {
	svc := newAppService(t, "app-a")
	tok, err := svc.GenerateAccessToken(uuid.New(), "kim@example.com", "Kim")
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if _, err := svc.ValidateAccessTokenForAudience(tok); !errors.Is(err, ErrAudienceMismatch) {
		t.Errorf("err = %v, want ErrAudienceMismatch", err)
	}
}
