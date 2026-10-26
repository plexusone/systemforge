package systemauth

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/plexusone/systemforge/identity"
)

// TestClientSecretHasher verifies that client secrets hashed with bcrypt
// or with Argon2id in PHC string format verify, and that a wrong secret or
// an empty hash does not.
func TestClientSecretHasher(t *testing.T) {
	ctx := context.Background()
	h := ClientSecretHasher{}
	bc, err := h.Hash(ctx, []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bcrypt.Cost(bc); err != nil {
		t.Fatalf("Hash did not return a bcrypt hash: %v", err)
	}
	argon, err := identity.HashPassword("s3cret", identity.DefaultArgon2idParams())
	if err != nil {
		t.Fatal(err)
	}
	for name, hash := range map[string][]byte{"bcrypt": bc, "argon2id": []byte(argon)} {
		if err := h.Compare(ctx, hash, []byte("s3cret")); err != nil {
			t.Errorf("%s: right secret refused: %v", name, err)
		}
		if err := h.Compare(ctx, hash, []byte("wrong")); err == nil {
			t.Errorf("%s: wrong secret accepted", name)
		}
	}
	if err := h.Compare(ctx, nil, []byte("")); err == nil {
		t.Error("empty hash accepted")
	}

	c := &Client{Type: ClientTypeConfidential, SecretHash: argon}
	if !c.ValidateSecret("s3cret") || c.ValidateSecret("wrong") {
		t.Error("ValidateSecret does not verify an Argon2id hash")
	}
}
