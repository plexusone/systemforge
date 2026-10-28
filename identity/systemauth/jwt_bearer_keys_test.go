package systemauth

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent"
	entcredential "github.com/plexusone/systemforge/identity/ent/credential"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/serviceaccount"
)

func TestJWTBearerKeysFindsUsableKey(t *testing.T) {
	f := newSAFixture(t)
	ctx := context.Background()
	acct := f.account("ci", "publish")
	k := f.key(acct, serviceaccount.KeyInput{})
	keys := NewEntJWTBearerKeys(f.db)

	jwk, err := keys.GetPublicKey(ctx, acct.Identifier, acct.Identifier, k.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if jwk.KeyID != k.KeyID || jwk.Algorithm != "ES256" || !jwk.Valid() || !jwk.IsPublic() {
		t.Errorf("jwk = %+v", jwk)
	}
	set, err := keys.GetPublicKeys(ctx, acct.Identifier, acct.Identifier)
	if err != nil || len(set.Keys) != 1 || set.Keys[0].KeyID != k.KeyID {
		t.Fatalf("GetPublicKeys = %+v, %v", set, err)
	}
}

// requireNotFound fails unless err is fosite.ErrNotFound.
func requireNotFound(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, fosite.ErrNotFound) {
		t.Errorf("%s: err = %v, want fosite.ErrNotFound", what, err)
	}
}

func TestJWTBearerKeysRefusals(t *testing.T) {
	f := newSAFixture(t)
	ctx := context.Background()
	keys := NewEntJWTBearerKeys(f.db)
	acct := f.account("ci")
	other := f.account("other")
	good := f.key(acct, serviceaccount.KeyInput{})
	otherKey := f.key(other, serviceaccount.KeyInput{})
	id := acct.Identifier

	_, err := keys.GetPublicKey(ctx, id, id, "no-such-key")
	requireNotFound(t, "unknown key", err)
	_, err = keys.GetPublicKey(ctx, id, id, otherKey.KeyID)
	requireNotFound(t, "another account's key", err)
	_, err = keys.GetPublicKey(ctx, other.Identifier, id, good.KeyID)
	requireNotFound(t, "issuer differs from subject", err)
	_, err = keys.GetPublicKey(ctx, "", "", good.KeyID)
	requireNotFound(t, "empty issuer and subject", err)

	// A human principal holding a key pair is not a service account.
	human, err := f.db.Principal.Get(ctx, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Credential.Create().SetPrincipalID(f.owner).SetType(entcredential.TypeKeypair).
		SetKeyID("human-key").SetKeyAlgorithm("ES256").SetPublicKey(good.PublicKeyPEM).SetActive(true).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = keys.GetPublicKey(ctx, human.Identifier, human.Identifier, "human-key")
	requireNotFound(t, "human principal", err)

	setKey := func(keyID string, update func(*ent.CredentialUpdate) *ent.CredentialUpdate) {
		t.Helper()
		if err := update(f.db.Credential.Update().Where(entcredential.KeyIDEQ(keyID))).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	revoked := f.key(acct, serviceaccount.KeyInput{})
	setKey(revoked.KeyID, func(u *ent.CredentialUpdate) *ent.CredentialUpdate { return u.SetRevoked(true) })
	expired := f.key(acct, serviceaccount.KeyInput{})
	setKey(expired.KeyID, func(u *ent.CredentialUpdate) *ent.CredentialUpdate {
		return u.SetExpiresAt(time.Now().Add(-time.Minute))
	})
	inactive := f.key(acct, serviceaccount.KeyInput{})
	setKey(inactive.KeyID, func(u *ent.CredentialUpdate) *ent.CredentialUpdate { return u.SetActive(false) })
	for name, k := range map[string]string{"revoked key": revoked.KeyID, "expired key": expired.KeyID, "inactive key": inactive.KeyID} {
		_, err := keys.GetPublicKey(ctx, id, id, k)
		requireNotFound(t, name, err)
	}
	set, err := keys.GetPublicKeys(ctx, id, id)
	if err != nil || len(set.Keys) != 1 || set.Keys[0].KeyID != good.KeyID {
		t.Errorf("GetPublicKeys lists unusable keys: %+v, %v", set, err)
	}

	// An inactive account, then an inactive organization.
	if err := f.db.Principal.UpdateOneID(acct.ID).SetActive(false).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = keys.GetPublicKey(ctx, id, id, good.KeyID)
	requireNotFound(t, "inactive account", err)
	_, err = keys.GetPublicKeys(ctx, id, id)
	requireNotFound(t, "inactive account's key set", err)
	_, err = keys.GetPublicKeyScopes(ctx, id, id, good.KeyID)
	requireNotFound(t, "inactive account's scopes", err)
	if err := f.db.Principal.UpdateOneID(acct.ID).SetActive(true).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.db.Organization.UpdateOneID(f.org.ID).SetActive(false).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = keys.GetPublicKey(ctx, id, id, good.KeyID)
	requireNotFound(t, "inactive organization", err)

	// A service principal outside any organization.
	loose, err := f.db.Principal.Create().SetType(entprincipal.TypeService).SetIdentifier("sa_loose").SetDisplayName("loose").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.Credential.Create().SetPrincipalID(loose.ID).SetType(entcredential.TypeKeypair).
		SetKeyID("loose-key").SetKeyAlgorithm("ES256").SetPublicKey(good.PublicKeyPEM).SetActive(true).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = keys.GetPublicKey(ctx, "sa_loose", "sa_loose", "loose-key")
	requireNotFound(t, "service principal without an organization", err)
}

func TestJWTBearerKeyScopes(t *testing.T) {
	f := newSAFixture(t)
	ctx := context.Background()
	keys := NewEntJWTBearerKeys(f.db)
	acct := f.account("ci", "publish", "read")
	k := f.key(acct, serviceaccount.KeyInput{Scopes: []string{"publish", "admin"}})
	got, err := keys.GetPublicKeyScopes(ctx, acct.Identifier, acct.Identifier, k.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"publish"}) {
		t.Errorf("scopes = %v, want the key's scopes the account allows: [publish]", got)
	}
}

func TestJWTBearerKeysJTI(t *testing.T) {
	f := newSAFixture(t)
	ctx := context.Background()
	keys := NewEntJWTBearerKeys(f.db)
	used, err := keys.IsJWTUsed(ctx, "jti-1")
	if err != nil || used {
		t.Fatalf("fresh jti used = %v, %v", used, err)
	}
	if err := keys.MarkJWTUsedForTime(ctx, "jti-1", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	used, err = keys.IsJWTUsed(ctx, "jti-1")
	if err != nil || !used {
		t.Fatalf("marked jti used = %v, %v", used, err)
	}
	if err := keys.MarkJWTUsedForTime(ctx, "jti-1", time.Now().Add(time.Minute)); !errors.Is(err, fosite.ErrJTIKnown) {
		t.Errorf("marking again err = %v, want ErrJTIKnown", err)
	}
}
