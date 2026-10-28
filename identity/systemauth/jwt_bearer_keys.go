package systemauth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/rfc7523"

	"github.com/plexusone/systemforge/identity/clientassertion"
	"github.com/plexusone/systemforge/identity/ent"
	entcredential "github.com/plexusone/systemforge/identity/ent/credential"
	"github.com/plexusone/systemforge/identity/ent/organization"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/serviceaccount"
)

// EntJWTBearerKeys is the key storage of the JWT-bearer grant (RFC 7523
// section 2.1) over the identity database: the public keys of service
// accounts, stored as key-pair credentials, and the used assertion IDs,
// shared with client assertions (clientassertion.JTIStore).
//
// An assertion is self-issued: its issuer and subject are both the
// account's identifier. A key is found only when
//
//   - the issuer equals the subject;
//   - the subject names an active service principal whose organization is
//     active;
//   - the key-pair credential belongs to that principal and is active,
//     unrevoked and unexpired.
//
// Every refusal returns fosite.ErrNotFound, so a caller cannot tell a
// missing key or account from a refused one.
type EntJWTBearerKeys struct {
	db   *ent.Client
	jtis *clientassertion.JTIStore
	now  func() time.Time
}

var _ rfc7523.RFC7523KeyStorage = (*EntJWTBearerKeys)(nil)

// NewEntJWTBearerKeys returns the JWT-bearer key storage over db.
func NewEntJWTBearerKeys(db *ent.Client) *EntJWTBearerKeys {
	return &EntJWTBearerKeys{db: db, jtis: clientassertion.NewJTIStore(db), now: time.Now}
}

// account returns the active service principal subject names, in an
// active organization, when issuer equals subject.
func (k *EntJWTBearerKeys) account(ctx context.Context, issuer, subject string) (*ent.Principal, error) {
	if issuer == "" || issuer != subject {
		return nil, fosite.ErrNotFound
	}
	p, err := k.db.Principal.Query().
		Where(
			entprincipal.IdentifierEQ(subject),
			entprincipal.TypeEQ(entprincipal.TypeService),
			entprincipal.Active(true),
			entprincipal.HasOrganizationWith(organization.Active(true)),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err)
	}
	return p, nil
}

// usableKeys selects p's usable key-pair credentials.
func (k *EntJWTBearerKeys) usableKeys(p *ent.Principal) *ent.CredentialQuery {
	return k.db.Credential.Query().Where(
		entcredential.PrincipalID(p.ID),
		entcredential.TypeEQ(entcredential.TypeKeypair),
		entcredential.Active(true),
		entcredential.Revoked(false),
		entcredential.Or(entcredential.ExpiresAtIsNil(), entcredential.ExpiresAtGT(k.now())),
	)
}

// key returns the account's usable credential with keyID.
func (k *EntJWTBearerKeys) key(ctx context.Context, issuer, subject, keyID string) (*ent.Principal, *ent.Credential, error) {
	p, err := k.account(ctx, issuer, subject)
	if err != nil {
		return nil, nil, err
	}
	cred, err := k.usableKeys(p).Where(entcredential.KeyIDEQ(keyID)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, nil, fosite.ErrServerError.WithWrap(err)
	}
	return p, cred, nil
}

// GetPublicKey implements rfc7523.RFC7523KeyStorage.
func (k *EntJWTBearerKeys) GetPublicKey(ctx context.Context, issuer, subject, keyID string) (*jose.JSONWebKey, error) {
	_, cred, err := k.key(ctx, issuer, subject, keyID)
	if err != nil {
		return nil, err
	}
	return credentialJWK(cred)
}

// GetPublicKeys implements rfc7523.RFC7523KeyStorage: every usable key of
// the account, for an assertion without a kid.
func (k *EntJWTBearerKeys) GetPublicKeys(ctx context.Context, issuer, subject string) (*jose.JSONWebKeySet, error) {
	p, err := k.account(ctx, issuer, subject)
	if err != nil {
		return nil, err
	}
	creds, err := k.usableKeys(p).All(ctx)
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err)
	}
	set := &jose.JSONWebKeySet{}
	for _, cred := range creds {
		jwk, err := credentialJWK(cred)
		if err != nil {
			continue // a stored key that does not parse cannot verify anything
		}
		set.Keys = append(set.Keys, *jwk)
	}
	if len(set.Keys) == 0 {
		return nil, fosite.ErrNotFound
	}
	return set, nil
}

// GetPublicKeyScopes implements rfc7523.RFC7523KeyStorage: the key's
// scopes intersected with the account's allowed scopes.
func (k *EntJWTBearerKeys) GetPublicKeyScopes(ctx context.Context, issuer, subject, keyID string) ([]string, error) {
	p, cred, err := k.key(ctx, issuer, subject, keyID)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, s := range cred.Scopes {
		if slices.Contains(p.AllowedScopes, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// IsJWTUsed implements rfc7523.RFC7523KeyStorage.
func (k *EntJWTBearerKeys) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	err := k.jtis.Valid(ctx, jti)
	if errors.Is(err, fosite.ErrJTIKnown) {
		return true, nil
	}
	return false, err
}

// MarkJWTUsedForTime implements rfc7523.RFC7523KeyStorage.
func (k *EntJWTBearerKeys) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return k.jtis.Mark(ctx, jti, exp)
}

// credentialJWK converts a stored key-pair credential to a JWK with its
// algorithm and key ID. A key that does not parse is not found.
func credentialJWK(cred *ent.Credential) (*jose.JSONWebKey, error) {
	if cred.KeyID == nil {
		return nil, fosite.ErrNotFound
	}
	pub, err := serviceaccount.ParsePublicKeyPEM(cred.PublicKey)
	if err != nil {
		return nil, fosite.ErrNotFound.WithWrap(err)
	}
	return &jose.JSONWebKey{Key: pub, KeyID: *cred.KeyID, Algorithm: cred.KeyAlgorithm, Use: "sig"}, nil
}
