package credential

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
)

func addApplication(t *testing.T, db *ent.Client, clientID string) uuid.UUID {
	t.Helper()
	p, err := db.Principal.Create().SetType(entprincipal.TypeApplication).SetIdentifier(clientID).SetDisplayName(clientID).Save(context.Background())
	if err != nil {
		t.Fatalf("application principal: %v", err)
	}
	return p.ID
}

func TestPasswords(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)

	if ok, err := svc.VerifyPassword(ctx, pid, "anything"); err != nil || ok {
		t.Errorf("verify without a password = %v, %v", ok, err)
	}
	if err := svc.CreatePassword(ctx, CreatePasswordInput{PrincipalID: pid, Password: "correct horse"}); err != nil {
		t.Fatalf("CreatePassword: %v", err)
	}
	row, err := db.Credential.Query().Only(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if strings.Contains(row.SecretHash, "correct horse") || !strings.HasPrefix(row.SecretHash, "$argon2id$") {
		t.Errorf("stored hash %q is not an Argon2id hash", row.SecretHash)
	}
	if ok, err := svc.VerifyPassword(ctx, pid, "correct horse"); err != nil || !ok {
		t.Fatalf("verify = %v, %v", ok, err)
	}
	if ok, err := svc.VerifyPassword(ctx, pid, "wrong"); err != nil || ok {
		t.Errorf("wrong password = %v, %v", ok, err)
	}
	if c, err := svc.GetByID(ctx, row.ID); err != nil || c.LastUsedAt == nil {
		t.Errorf("last use not recorded: %+v, %v", c, err)
	}

	// Updating replaces the password instead of adding a second one.
	if err := svc.UpdatePassword(ctx, pid, "battery staple"); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}
	if n, err := db.Credential.Query().Count(ctx); err != nil || n != 1 {
		t.Errorf("password credentials = %d, %v; want 1", n, err)
	}
	if ok, err := svc.VerifyPassword(ctx, pid, "correct horse"); err != nil || ok {
		t.Errorf("old password after update = %v, %v", ok, err)
	}
	if ok, err := svc.VerifyPassword(ctx, pid, "battery staple"); err != nil || !ok {
		t.Errorf("new password = %v, %v", ok, err)
	}

	// A revoked password does not verify.
	if err := svc.Revoke(ctx, row.ID, "reset"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, err := svc.VerifyPassword(ctx, pid, "battery staple"); err != nil || ok {
		t.Errorf("revoked password = %v, %v", ok, err)
	}
}

func TestAPIKeys(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)

	key, err := svc.CreateAPIKey(ctx, CreateAPIKeyInput{PrincipalID: pid, Name: "ci", Scopes: []string{"read"}})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if !strings.HasPrefix(key.PlainKey, APIKeyPrefix) || key.Prefix != key.PlainKey[:12] {
		t.Errorf("key %q prefix %q", key.PlainKey, key.Prefix)
	}
	row, err := db.Credential.Get(ctx, key.Credential.ID)
	if err != nil || strings.Contains(row.SecretHash, key.PlainKey) {
		t.Fatalf("stored key: %+v, %v", row, err)
	}
	c, err := svc.ValidateAPIKey(ctx, key.PlainKey)
	if err != nil || c.PrincipalID != pid || len(c.Scopes) != 1 {
		t.Fatalf("ValidateAPIKey = %+v, %v", c, err)
	}
	if c, err := svc.GetByID(ctx, key.Credential.ID); err != nil || c.LastUsedAt == nil {
		t.Errorf("last use not recorded: %+v, %v", c, err)
	}

	expired, err := svc.CreateAPIKey(ctx, CreateAPIKeyInput{PrincipalID: pid, ExpiresAt: new(time.Now().Add(-time.Minute))})
	if err != nil {
		t.Fatalf("CreateAPIKey expired: %v", err)
	}
	revoked, err := svc.CreateAPIKey(ctx, CreateAPIKeyInput{PrincipalID: pid})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if err := svc.Revoke(ctx, revoked.Credential.ID, "leaked"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	for name, plain := range map[string]string{
		"expired":     expired.PlainKey,
		"revoked":     revoked.PlainKey,
		"no prefix":   strings.TrimPrefix(key.PlainKey, APIKeyPrefix),
		"wrong":       key.PlainKey + "x",
		"empty":       "",
		"bare prefix": APIKeyPrefix,
	} {
		if _, err := svc.ValidateAPIKey(ctx, plain); err == nil {
			t.Errorf("%s key validated", name)
		}
	}

	keys, err := svc.ListAPIKeys(ctx, pid)
	if err != nil || len(keys) != 3 {
		t.Errorf("ListAPIKeys = %d, %v; want 3", len(keys), err)
	}
	if other, err := svc.ListAPIKeys(ctx, uuid.New()); err != nil || len(other) != 0 {
		t.Errorf("another principal's keys = %d, %v", len(other), err)
	}
}

func TestClientSecrets(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	app := addApplication(t, db, "billing-service")

	first, err := svc.CreateClientSecret(ctx, CreateClientSecretInput{PrincipalID: app, Name: "first"})
	if err != nil {
		t.Fatalf("CreateClientSecret: %v", err)
	}
	// A second secret, as during rotation: both validate.
	second, err := svc.CreateClientSecret(ctx, CreateClientSecretInput{PrincipalID: app, Name: "second"})
	if err != nil {
		t.Fatalf("CreateClientSecret: %v", err)
	}
	for _, s := range []*GeneratedClientSecret{first, second} {
		c, err := svc.ValidateClientSecret(ctx, "billing-service", s.PlainSecret)
		if err != nil || c.ID != s.Credential.ID {
			t.Errorf("ValidateClientSecret(%s) = %+v, %v", s.Credential.Name, c, err)
		}
	}
	if c, err := svc.GetByID(ctx, first.Credential.ID); err != nil || c.LastUsedAt == nil {
		t.Errorf("last use not recorded: %+v, %v", c, err)
	}

	if err := svc.Revoke(ctx, first.Credential.ID, "rotated"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	expired, err := svc.CreateClientSecret(ctx, CreateClientSecretInput{PrincipalID: app, ExpiresAt: new(time.Now().Add(-time.Second))})
	if err != nil {
		t.Fatalf("CreateClientSecret: %v", err)
	}
	for name, tc := range map[string][2]string{
		"revoked":        {"billing-service", first.PlainSecret},
		"expired":        {"billing-service", expired.PlainSecret},
		"wrong secret":   {"billing-service", "nope"},
		"unknown client": {"other-service", second.PlainSecret},
	} {
		if _, err := svc.ValidateClientSecret(ctx, tc[0], tc[1]); err == nil {
			t.Errorf("%s validated", name)
		}
	}

	// A human principal with the same identifier is not a client.
	if _, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier("kim@example.com").SetDisplayName("Kim").Save(ctx); err != nil {
		t.Fatalf("human: %v", err)
	}
	if _, err := svc.ValidateClientSecret(ctx, "kim@example.com", second.PlainSecret); err == nil {
		t.Error("a human identifier validated as a client")
	}
}

// TestClientSecretWithCorruptHash verifies that a stored secret whose hash
// cannot be parsed is reported, not silently skipped.
func TestClientSecretWithCorruptHash(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	app := addApplication(t, db, "svc")
	s, err := svc.CreateClientSecret(ctx, CreateClientSecretInput{PrincipalID: app})
	if err != nil {
		t.Fatalf("CreateClientSecret: %v", err)
	}
	if err := db.Credential.UpdateOneID(s.Credential.ID).SetSecretHash("not-a-hash").Exec(ctx); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	_, err = svc.ValidateClientSecret(ctx, "svc", s.PlainSecret)
	if err == nil || !errors.Is(err, ErrCorruptCredential) {
		t.Errorf("corrupt hash error = %v, want ErrCorruptCredential", err)
	}
}

func TestKeypairs(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)
	const pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n"

	kp, err := svc.CreateKeypair(ctx, CreateKeypairInput{PrincipalID: pid, Name: "deploy", KeyAlgorithm: "EdDSA", PublicKeyPEM: pem, Scopes: []string{"deploy"}})
	if err != nil {
		t.Fatalf("CreateKeypair: %v", err)
	}
	got, err := svc.GetKeypairByKeyID(ctx, kp.KeyID)
	if err != nil || got.PublicKeyPEM != pem || got.KeyAlgorithm != "EdDSA" || got.Credential.PrincipalID != pid {
		t.Fatalf("GetKeypairByKeyID = %+v, %v", got, err)
	}

	expired, err := svc.CreateKeypair(ctx, CreateKeypairInput{PrincipalID: pid, KeyAlgorithm: "EdDSA", PublicKeyPEM: pem, ExpiresAt: new(time.Now().Add(-time.Second))})
	if err != nil {
		t.Fatalf("CreateKeypair: %v", err)
	}
	if _, err := svc.GetKeypairByKeyID(ctx, expired.KeyID); err == nil {
		t.Error("expired keypair returned")
	}
	if err := svc.Revoke(ctx, kp.Credential.ID, "rotated"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.GetKeypairByKeyID(ctx, kp.KeyID); err == nil {
		t.Error("revoked keypair returned")
	}
	if _, err := svc.GetKeypairByKeyID(ctx, "unknown"); err == nil {
		t.Error("unknown key ID returned a keypair")
	}
	if list, err := svc.ListKeypairs(ctx, pid); err != nil || len(list) != 2 {
		t.Errorf("ListKeypairs = %d, %v; want 2", len(list), err)
	}
}

func TestCommonOperations(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)
	key, err := svc.CreateAPIKey(ctx, CreateAPIKeyInput{PrincipalID: pid})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if err := svc.UpdateLastUsed(ctx, key.Credential.ID, "192.0.2.1"); err != nil {
		t.Fatalf("UpdateLastUsed: %v", err)
	}
	c, err := svc.GetByID(ctx, key.Credential.ID)
	if err != nil || c.LastUsedIP != "192.0.2.1" || c.LastUsedAt == nil {
		t.Errorf("after UpdateLastUsed = %+v, %v", c, err)
	}
	if err := svc.Revoke(ctx, key.Credential.ID, "done"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	c, err = svc.GetByID(ctx, key.Credential.ID)
	if err != nil || !c.Revoked || c.Active || c.RevokedReason != "done" || c.RevokedAt == nil {
		t.Errorf("after Revoke = %+v, %v", c, err)
	}
	if _, err := svc.GetByID(ctx, uuid.New()); err == nil {
		t.Error("GetByID of an unknown credential succeeded")
	}
	if err := svc.Revoke(ctx, uuid.New(), "x"); err == nil {
		t.Error("revoking an unknown credential succeeded")
	}
	if err := svc.UpdateLastUsed(ctx, uuid.New(), ""); err == nil {
		t.Error("UpdateLastUsed of an unknown credential succeeded")
	}
}
