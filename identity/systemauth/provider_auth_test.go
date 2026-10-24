package systemauth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// newAuthTestIdentity stores an active identity with the given email and
// returns the identity provider holding it.
func newAuthTestIdentity(t *testing.T, email string) (*EmbeddedIdentityProvider, *Identity) {
	t.Helper()
	ip := NewEmbeddedIdentityProvider(NewMemoryStorage())
	identity := &Identity{ID: uuid.New(), State: IdentityStateActive, Traits: IdentityTraits{Email: email}}
	if err := ip.CreateIdentity(context.Background(), identity); err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	return ip, identity
}

// TestAuthenticateRefusesUnverifiedMethods verifies that a method the
// provider has no verifier for never signs anyone in, whatever token the
// request carries.
func TestAuthenticateRefusesUnverifiedMethods(t *testing.T) {
	ip, _ := newAuthTestIdentity(t, "victim@example.com")
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
