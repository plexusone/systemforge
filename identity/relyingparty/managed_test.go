package relyingparty

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// TestResolveManagedPrincipal verifies that a managed identity, which has
// no email, is created on first sign-in, found by subject afterwards, and
// never linked by email.
func TestResolveManagedPrincipal(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryPrincipalStore()
	now := time.Now()

	first, err := ResolvePrincipal(ctx, store, VerifiedIdentity{Subject: "sf-learner", Name: "Learner", Managed: true}, now)
	if err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	if !first.Managed || first.Email != "" || first.EmailVerified || first.Name != "Learner" {
		t.Errorf("principal = %+v", first)
	}
	again, err := ResolvePrincipal(ctx, store, VerifiedIdentity{Subject: "sf-learner", Managed: true}, now)
	if err != nil || again.ID != first.ID {
		t.Errorf("second sign-in = %+v, %v; want %s", again, err, first.ID)
	}

	// Several managed principals coexist without emails.
	other, err := ResolvePrincipal(ctx, store, VerifiedIdentity{Subject: "sf-other", Managed: true}, now)
	if err != nil || other.ID == first.ID {
		t.Errorf("other managed = %+v, %v", other, err)
	}
	if _, err := store.FindByEmail(ctx, ""); !errors.Is(err, ErrPrincipalNotFound) {
		t.Errorf("FindByEmail(\"\") = %v, want ErrPrincipalNotFound", err)
	}

	// A managed identity that carries an email is inconsistent.
	if _, err := ResolvePrincipal(ctx, store, VerifiedIdentity{Subject: "sf-odd", Email: "x@example.com", EmailVerified: true, Managed: true}, now); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("managed with email = %v, want ErrInvalidToken", err)
	}
	// An unmanaged identity without an email is still refused.
	if _, err := ResolvePrincipal(ctx, store, VerifiedIdentity{Subject: "sf-plain"}, now); !errors.Is(err, ErrEmailNotVerified) {
		t.Errorf("unmanaged without email = %v, want ErrEmailNotVerified", err)
	}

	u, err := json.Marshal(toUser(first, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(u, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := fields["email"]; ok || fields["managed"] != true {
		t.Errorf("frontend user = %s", u)
	}
}

func TestIdentityFromClaimsManaged(t *testing.T) {
	idt := idToken("sf-learner", map[string]any{"sub": "sf-learner", "managed": true})
	id, err := IdentityFromClaims(idt, nil)
	if err != nil || !id.Managed {
		t.Errorf("from ID token = %+v, %v", id, err)
	}
	id, err = IdentityFromClaims(idToken("sf-learner", map[string]any{}),
		&UserInfo{Subject: "sf-learner", Raw: map[string]any{"managed": true}})
	if err != nil || !id.Managed {
		t.Errorf("from userinfo = %+v, %v", id, err)
	}
	id, err = IdentityFromClaims(idToken("a", map[string]any{"managed": "true"}), nil)
	if err != nil || id.Managed {
		t.Errorf("non-boolean claim = %+v, %v; want unmanaged", id, err)
	}
}

func idToken(subject string, raw map[string]any) *IDTokenClaims {
	c := &IDTokenClaims{Raw: raw}
	c.Subject = subject
	return c
}
