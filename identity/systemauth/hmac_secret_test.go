package systemauth

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test secrets share their first 32 bytes, which is all Fosite keys its
// HMAC with, so the tests also show that the whole secret counts.
var (
	testHMACSecretPrefix = strings.Repeat("s", MinHMACSecretLength)
	testHMACSecret       = testHMACSecretPrefix + "-current"
	testOtherHMACSecret  = testHMACSecretPrefix + "-verification"
)

// newHMACTestServer is the refresh test server over st with the given
// token HMAC secrets, standing for one instance or one process lifetime.
func newHMACTestServer(t *testing.T, st Storage, secret, verification string) *Server {
	t.Helper()
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Tokens: TokenConfig{HMACSecret: secret, HMACVerificationSecret: verification},
		Clients: []ClientConfig{{
			ID:            "spa",
			Type:          "public",
			Name:          "SPA",
			RedirectURIs:  []string{testRPCB},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
	},
		WithSessionProvider(NewDefaultSessionProvider(WithTrustedUserIDHeader("X-User-ID", TrustAllRequests))),
		WithStorage(st),
	)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

// grantRefreshToken signs a new person in at s and returns the refresh
// token it issues.
func grantRefreshToken(t *testing.T, s *Server) string {
	t.Helper()
	body := exchangeCode(t, s, authorizeCode(t, s, "openid offline_access", headerUser(newPrincipal(t, s))))
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh token: %v", body)
	}
	return rt
}

// TestHMACSecretSurvivesRestart: with tokens.hmac_secret set, a refresh
// token and an authorization code issued by one process are accepted by
// the next, which shares only the storage and the configuration.
func TestHMACSecretSurvivesRestart(t *testing.T) {
	st := NewMemoryStorage()
	before := newHMACTestServer(t, st, testHMACSecret, "")
	rt := grantRefreshToken(t, before)
	code := authorizeCode(t, before, "openid offline_access", headerUser(newPrincipal(t, before)))

	after := newHMACTestServer(t, st, testHMACSecret, "")
	if status, body := refresh(t, after, rt); status != http.StatusOK {
		t.Fatalf("refresh after restart: %d %v", status, body)
	}
	exchangeCode(t, after, code)
}

// TestHMACSecretUnsetDoesNotSurviveRestart pins the behaviour the setting
// fixes: without it, each process signs with its own random secret.
func TestHMACSecretUnsetDoesNotSurviveRestart(t *testing.T) {
	st := NewMemoryStorage()
	rt := grantRefreshToken(t, newHMACTestServer(t, st, "", ""))
	if status, body := refresh(t, newHMACTestServer(t, st, "", ""), rt); status == http.StatusOK {
		t.Fatalf("refresh with another process's random secret succeeded: %v", body)
	}
}

// TestHMACSecretRotation follows the rotation rule from N-1 (old) to N
// (next): pre-stage N as the verification secret, promote it, and retire
// N-1. At each step tokens already issued keep working, including after a
// rollback of the promotion, and a token signed only with a retired secret
// is refused.
func TestHMACSecretRotation(t *testing.T) {
	old, next := testOtherHMACSecret, testHMACSecret
	st := NewMemoryStorage()
	before := newHMACTestServer(t, st, old, "")
	oldRT := grantRefreshToken(t, before)
	staleRT := grantRefreshToken(t, before)

	// Pre-stage: N-1 still signs; N is accepted.
	prestaged := newHMACTestServer(t, st, old, next)
	if status, body := refresh(t, prestaged, oldRT); status != http.StatusOK {
		t.Fatalf("pre-staged: refresh of an N-1 token: %d %v", status, body)
	}

	// Promote: N signs; N-1 is accepted.
	promoted := newHMACTestServer(t, st, next, old)
	nextRT := grantRefreshToken(t, promoted)
	nextRT2 := grantRefreshToken(t, promoted)
	if status, body := refresh(t, promoted, grantRefreshToken(t, prestaged)); status != http.StatusOK {
		t.Fatalf("promoted: refresh of an N-1 token: %d %v", status, body)
	}

	// Roll the promotion back: tokens signed with N keep working.
	if status, body := refresh(t, newHMACTestServer(t, st, old, next), nextRT); status != http.StatusOK {
		t.Fatalf("rolled back: refresh of an N token: %d %v", status, body)
	}

	// Retire N-1.
	retired := newHMACTestServer(t, st, next, "")
	if status, body := refresh(t, retired, nextRT2); status != http.StatusOK {
		t.Fatalf("retired: refresh of an N token: %d %v", status, body)
	}
	if status, body := refresh(t, retired, staleRT); status == http.StatusOK {
		t.Fatalf("retired: a token signed only with N-1 was accepted: %v", body)
	}
}

// TestHMACKeyUsesWholeSecret: Fosite keys its HMAC with only the first 32
// bytes of the secret, so two secrets sharing those bytes must still give
// different keys.
func TestHMACKeyUsesWholeSecret(t *testing.T) {
	if string(hmacKey(testHMACSecret)) == string(hmacKey(testOtherHMACSecret)) {
		t.Fatal("secrets differing after byte 32 gave the same key")
	}
	if n := len(hmacKey(testHMACSecret)); n != 32 {
		t.Fatalf("key length %d, want 32", n)
	}
}

func TestHMACSecretValidation(t *testing.T) {
	short := strings.Repeat("x", MinHMACSecretLength-1)
	cases := []struct {
		name                 string
		secret, verification string
		wantErr              string
	}{
		{"unset", "", "", ""},
		{"set", testHMACSecret, "", ""},
		{"rotating", testHMACSecret, testOtherHMACSecret, ""},
		{"short", short, "", "tokens.hmac_secret must be at least"},
		{"verification without current", "", testOtherHMACSecret, "requires tokens.hmac_secret"},
		{"short verification", testHMACSecret, short, "tokens.hmac_verification_secret must be at least"},
		{"verification equals current", testHMACSecret, testHMACSecret, "must differ"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig(testIssuer)
			cfg.Tokens.HMACSecret, cfg.Tokens.HMACVerificationSecret = tc.secret, tc.verification
			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate = %v, want ErrInvalidConfig containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestHMACSecretFromEnvironment: the loader expands the secrets from the
// environment without re-expanding a "$" inside them.
func TestHMACSecretFromEnvironment(t *testing.T) {
	secret := testHMACSecretPrefix + "$HOME"
	t.Setenv("TEST_SYSTEMAUTH_HMAC_SECRET", secret)
	t.Setenv("TEST_SYSTEMAUTH_HMAC_VERIFICATION_SECRET", testOtherHMACSecret)
	path := filepath.Join(t.TempDir(), "systemauth.yaml")
	yaml := "issuer: " + testIssuer + "\ntokens:\n  hmac_secret: ${TEST_SYSTEMAUTH_HMAC_SECRET}\n  hmac_verification_secret: ${TEST_SYSTEMAUTH_HMAC_VERIFICATION_SECRET}\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Tokens.HMACSecret != secret || cfg.Tokens.HMACVerificationSecret != testOtherHMACSecret {
		t.Fatalf("tokens = %q, %q", cfg.Tokens.HMACSecret, cfg.Tokens.HMACVerificationSecret)
	}
}
