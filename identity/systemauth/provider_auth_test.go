package systemauth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/security"
)

// newAuthTestIdentity stores an active identity with the given email and
// returns the identity provider holding it.
func newAuthTestIdentity(t *testing.T, email string) *EmbeddedIdentityProvider {
	t.Helper()
	ip := NewEmbeddedIdentityProvider(NewMemoryStorage())
	identity := &Identity{ID: uuid.New(), State: IdentityStateActive, Traits: IdentityTraits{Email: email}}
	if err := ip.CreateIdentity(context.Background(), identity); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	return ip
}

// TestPasswordLoginLockout verifies that failed password attempts lock the
// identifier, that a locked identifier is refused even with the right
// password, and that unknown identifiers lock the same way, so the lockout
// does not reveal which accounts exist.
func TestPasswordLoginLockout(t *testing.T) {
	ctx := context.Background()
	ip := newAuthTestIdentity(t, "lin@example.com")
	verifier := func(_ context.Context, _ uuid.UUID, password string) (bool, error) {
		return password == "right", nil
	}
	lockout := security.NewLockout(security.NewMemoryLockoutStore(), security.WithMaxAttempts(3))
	p := NewEmbeddedAuthProvider(ip, WithPasswordVerifier(verifier), WithLockout(lockout))

	login := func(email, password string) error {
		_, err := p.Authenticate(ctx, &AuthenticateRequest{Method: AuthMethodPassword, Identifier: email, Password: password})
		return err
	}

	for _, email := range []string{"lin@example.com", "nobody@example.com"} {
		for i := range 2 {
			if err := login(email, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("%s attempt %d: %v, want ErrInvalidCredentials", email, i+1, err)
			}
		}
		if err := login(email, "wrong"); !errors.Is(err, ErrAccountLocked) {
			t.Fatalf("%s third failure: %v, want ErrAccountLocked", email, err)
		}
		if err := login(email, "right"); !errors.Is(err, ErrAccountLocked) {
			t.Errorf("%s while locked with the right password: %v, want ErrAccountLocked", email, err)
		}
	}

	// A success clears earlier failures.
	if err := lockout.Reset(ctx, "lin@example.com"); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if err := login("lin@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("after reset: %v", err)
	}
	if err := login("LIN@example.com", "right"); err != nil {
		t.Fatalf("right password: %v", err)
	}
	for i := range 2 {
		if err := login("lin@example.com", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure %d after success: %v, want ErrInvalidCredentials", i+1, err)
		}
	}
}

// TestPasswordLoginLockoutDefault verifies that the provider limits
// attempts without being configured to.
func TestPasswordLoginLockoutDefault(t *testing.T) {
	ip := newAuthTestIdentity(t, "lin@example.com")
	p := NewEmbeddedAuthProvider(ip, WithPasswordVerifier(func(context.Context, uuid.UUID, string) (bool, error) { return false, nil }))
	var err error
	for range security.DefaultLockoutConfig().MaxAttempts + 1 {
		_, err = p.Authenticate(context.Background(), &AuthenticateRequest{Method: AuthMethodPassword, Identifier: "lin@example.com", Password: "guess"})
	}
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("after %d failures: %v, want ErrAccountLocked", security.DefaultLockoutConfig().MaxAttempts+1, err)
	}
}

// TestPasswordLoginUnknownAccountCostsAVerification verifies that an
// unknown or inactive account spends a password hash verification, so it
// cannot be told from a wrong password by timing, and that a missing
// verifier is reported before any account lookup.
func TestPasswordLoginUnknownAccountCostsAVerification(t *testing.T) {
	ctx := context.Background()
	ip := newAuthTestIdentity(t, "lin@example.com")
	if err := ip.CreateIdentity(ctx, &Identity{ID: uuid.New(), State: IdentityStateInactive, Traits: IdentityTraits{Email: "gone@example.com"}}); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}

	unconfigured := NewEmbeddedAuthProvider(ip, WithLockout(nil))
	for _, email := range []string{"lin@example.com", "nobody@example.com"} {
		if _, err := unconfigured.Authenticate(ctx, &AuthenticateRequest{Method: AuthMethodPassword, Identifier: email}); !errors.Is(err, ErrPasswordAuthNotConfigured) {
			t.Errorf("%s without a verifier: %v, want ErrPasswordAuthNotConfigured", email, err)
		}
	}

	// The real burn must run without failing.
	burnArgon2idVerification("guess")

	burned := 0
	burn := burnVerification
	burnVerification = func(string) { burned++ }
	t.Cleanup(func() { burnVerification = burn })

	verified := 0
	p := NewEmbeddedAuthProvider(ip, WithLockout(nil), WithPasswordVerifier(func(context.Context, uuid.UUID, string) (bool, error) {
		verified++
		return false, nil
	}))
	for _, tc := range []struct {
		email            string
		burned, verified int
	}{
		{"nobody@example.com", 1, 0},
		{"gone@example.com", 1, 0},
		{"lin@example.com", 0, 1},
	} {
		burned, verified = 0, 0
		if _, err := p.Authenticate(ctx, &AuthenticateRequest{Method: AuthMethodPassword, Identifier: tc.email, Password: "guess"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%s: %v, want ErrInvalidCredentials", tc.email, err)
		}
		if burned != tc.burned || verified != tc.verified {
			t.Errorf("%s: %d placeholder and %d real verifications, want %d and %d", tc.email, burned, verified, tc.burned, tc.verified)
		}
	}
}

// TestAuthenticateRefusesUnverifiedMethods verifies that a method the
// provider has no verifier for never signs anyone in, whatever token the
// request carries.
func TestAuthenticateRefusesUnverifiedMethods(t *testing.T) {
	ip := newAuthTestIdentity(t, "victim@example.com")
	p := NewEmbeddedAuthProvider(ip)
	for _, m := range []AuthMethod{AuthMethodOIDC, AuthMethodWebAuthn, AuthMethodTOTP, "", "other"} {
		sess, err := p.Authenticate(context.Background(), &AuthenticateRequest{
			Identifier: "victim@example.com", Method: m, OIDCToken: "anything",
		})
		if !errors.Is(err, ErrUnsupportedAuthMethod) || sess != nil {
			t.Errorf("Authenticate(method %q) = %v, %v; want ErrUnsupportedAuthMethod", m, sess, err)
		}
	}
}
