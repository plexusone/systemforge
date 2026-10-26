package systemauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"

	"github.com/plexusone/systemforge/identity/ent/oauthapp"
	"github.com/plexusone/systemforge/identity/ent/oauthappsecret"
)

// secretAccepted reports whether the confidentialID client authenticates with secret,
// as the token endpoint checks it.
func secretAccepted(t *testing.T, st *EntStorage, secret string) bool {
	t.Helper()
	ctx := context.Background()
	fc, err := st.GetClient(ctx, confidentialID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	h := ClientSecretHasher{}
	if h.Compare(ctx, fc.GetHashedSecret(), []byte(secret)) == nil {
		return true
	}
	rc, ok := fc.(fosite.ClientWithSecretRotation)
	if !ok {
		t.Fatal("client does not support secret rotation")
	}
	for _, rh := range rc.GetRotatedHashes() {
		if h.Compare(ctx, rh, []byte(secret)) == nil {
			return true
		}
	}
	return false
}

// TestRotateClientSecretKeepsPrevious verifies that a rotation keeps the
// current secret (N) and the one it replaced (N-1) valid and revokes only
// older secrets, and that revoking N rolls back to N-1.
func TestRotateClientSecretKeepsPrevious(t *testing.T) {
	db := newEntTestClient(t, "rotate_keeps_previous")
	ctx := context.Background()
	st := NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))
	c, err := NewClientFromConfig(ClientConfig{ID: confidentialID, Type: "confidential", Name: "Web", Secret: "s0", RedirectURIs: []string{testRPCB}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}

	r1, err := st.RotateClientSecret(ctx, confidentialID)
	if err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	if r1.Secret == "" || r1.Prefix != r1.Secret[:8] {
		t.Fatalf("rotation returned %+v", r1)
	}
	for _, s := range []string{"s0", r1.Secret} {
		if !secretAccepted(t, st, s) {
			t.Errorf("after the first rotation %q is refused", s)
		}
	}

	r2, err := st.RotateClientSecret(ctx, confidentialID)
	if err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	for s, want := range map[string]bool{"s0": false, r1.Secret: true, r2.Secret: true} {
		if got := secretAccepted(t, st, s); got != want {
			t.Errorf("after the second rotation %q accepted=%v, want %v", s, got, want)
		}
	}
	revoked, err := db.OAuthAppSecret.Query().Where(oauthappsecret.RevokedEQ(true)).Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if revoked != 1 {
		t.Errorf("revoked secrets = %d, want 1 (N-2)", revoked)
	}

	// Roll back: the new secret is bad, so revoke it; N-1 is current again.
	if err := st.RevokeClientSecret(ctx, confidentialID, r2.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if secretAccepted(t, st, r2.Secret) || !secretAccepted(t, st, r1.Secret) {
		t.Error("revoking N did not leave N-1 as the only valid secret")
	}
	if err := st.RevokeClientSecret(ctx, confidentialID, r2.ID); !errors.Is(err, ErrClientSecretNotFound) {
		t.Errorf("revoking twice: %v, want ErrClientSecretNotFound", err)
	}
	if err := st.RevokeClientSecret(ctx, "other", r1.ID); !errors.Is(err, ErrClientSecretNotFound) {
		t.Errorf("revoking through another client: %v, want ErrClientSecretNotFound", err)
	}
	if err := st.RevokeClientSecret(ctx, confidentialID, uuid.New()); !errors.Is(err, ErrClientSecretNotFound) {
		t.Errorf("revoking an unknown secret: %v, want ErrClientSecretNotFound", err)
	}
}

// TestOnlyTwoNewestClientSecretsAuthenticate verifies that a secret older
// than N-1 does not authenticate even when it was never revoked.
func TestOnlyTwoNewestClientSecretsAuthenticate(t *testing.T) {
	db := newEntTestClient(t, "two_newest_secrets")
	ctx := context.Background()
	st := NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))
	c, err := NewClientFromConfig(ClientConfig{ID: confidentialID, Type: "confidential", Name: "Web", RedirectURIs: []string{testRPCB}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	app, err := db.OAuthApp.Query().Where(oauthapp.ClientIDEQ(confidentialID)).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i, s := range []string{"n-2", "n-1", "n"} {
		h, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.OAuthAppSecret.Create().SetAppID(app.ID).SetSecretHash(string(h)).SetSecretPrefix(s).
			SetCreatedAt(now.Add(time.Duration(i) * time.Minute)).Save(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for s, want := range map[string]bool{"n-2": false, "n-1": true, "n": true} {
		if got := secretAccepted(t, st, s); got != want {
			t.Errorf("%s accepted=%v, want %v", s, got, want)
		}
	}
}

// TestRotateClientSecretRefusals verifies that public and unknown clients
// cannot rotate a secret.
func TestRotateClientSecretRefusals(t *testing.T) {
	db := newEntTestClient(t, "rotate_refusals")
	ctx := context.Background()
	st := NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))
	c, err := NewClientFromConfig(ClientConfig{ID: "spa", Type: "public", Name: "SPA", RedirectURIs: []string{testRPCB}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RotateClientSecret(ctx, "spa"); !errors.Is(err, ErrPublicClient) {
		t.Errorf("public client: %v, want ErrPublicClient", err)
	}
	if _, err := st.RotateClientSecret(ctx, "missing"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("unknown client: %v, want ErrClientNotFound", err)
	}
}
