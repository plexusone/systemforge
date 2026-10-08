package systemauth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// TestEmptyEmailNeverMatches verifies that the in-memory stores, password
// login, and federation sync never treat a missing email as one that
// matches, so a managed principal (no email) cannot be found or adopted
// by email.
func TestEmptyEmailNeverMatches(t *testing.T) {
	ctx := context.Background()

	ms := NewMemoryStorage()
	if err := ms.CreateHuman(ctx, &HumanPrincipal{DisplayName: "No Email", Active: true}); !errors.Is(err, ErrEmailRequired) {
		t.Errorf("MemoryStorage.CreateHuman without email = %v, want ErrEmailRequired", err)
	}
	if err := ms.CreateHuman(ctx, &HumanPrincipal{Email: "kim@example.com", Active: true}); err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if _, err := ms.GetHumanByEmail(ctx, ""); !errors.Is(err, ErrPrincipalNotFound) {
		t.Errorf("GetHumanByEmail(\"\") = %v, want ErrPrincipalNotFound", err)
	}

	dir := NewMemoryPrincipalDirectory()
	for range 2 {
		if err := dir.AddPrincipal(HumanPrincipal{ID: uuid.New(), DisplayName: "Learner", Active: true, EmailVerified: true}); err != nil {
			t.Fatalf("AddPrincipal without email: %v", err)
		}
	}
	if _, err := dir.FindByVerifiedEmail(ctx, ""); !errors.Is(err, ErrPrincipalNotFound) {
		t.Errorf("FindByVerifiedEmail(\"\") = %v, want ErrPrincipalNotFound", err)
	}

	resp, err := NewDefaultIdentitySyncHandler(ms).SyncIdentity(ctx, &IdentitySyncRequest{
		Action:   "create",
		Identity: &GlobalIdentity{ID: uuid.New(), DisplayName: "No Email"},
	})
	if err != nil {
		t.Fatalf("SyncIdentity: %v", err)
	}
	if resp.Status != "failed" {
		t.Errorf("federated create without email = %+v, want failed", resp)
	}
}

func TestPasswordLoginRefusesEmptyIdentifier(t *testing.T) {
	p := &EmbeddedAuthProvider{}
	for _, id := range []string{"", "  "} {
		if _, err := p.Authenticate(context.Background(), &AuthenticateRequest{Identifier: id, Method: AuthMethodPassword}); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("Authenticate(%q) = %v, want ErrInvalidCredentials", id, err)
		}
	}
}
