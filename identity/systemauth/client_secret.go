package systemauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"

	"github.com/plexusone/systemforge/identity"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/oauthappsecret"
)

// argon2idPrefix marks an Argon2id hash in the PHC string format written by
// identity.HashPassword.
const argon2idPrefix = "$argon2id$"

// ClientSecretHasher is the fosite.Hasher for OAuth client secrets. It
// writes bcrypt hashes and verifies both bcrypt hashes and Argon2id hashes
// in PHC string format ($argon2id$...), so client secrets stored with
// either work.
type ClientSecretHasher struct{}

var _ fosite.Hasher = ClientSecretHasher{}

// Hash returns the bcrypt hash of a client secret.
func (ClientSecretHasher) Hash(_ context.Context, data []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(data, bcrypt.DefaultCost)
}

// Compare returns nil when data is the secret hash was made from.
func (ClientSecretHasher) Compare(_ context.Context, hash, data []byte) error {
	if len(hash) == 0 {
		return errors.New("systemauth: empty client secret hash")
	}
	if strings.HasPrefix(string(hash), argon2idPrefix) {
		ok, err := identity.VerifyPassword(string(data), string(hash))
		if err != nil {
			return fmt.Errorf("systemauth: verify client secret: %w", err)
		}
		if !ok {
			return errors.New("systemauth: client secret mismatch")
		}
		return nil
	}
	return bcrypt.CompareHashAndPassword(hash, data)
}

// ActiveClientSecretHashes returns the hashes of the secrets an OAuth app
// authenticates with, newest first: those neither revoked nor expired.
func ActiveClientSecretHashes(ctx context.Context, db *ent.Client, appID uuid.UUID) ([]string, error) {
	secrets, err := db.OAuthAppSecret.Query().
		Where(
			oauthappsecret.AppIDEQ(appID),
			oauthappsecret.RevokedEQ(false),
			oauthappsecret.Or(oauthappsecret.ExpiresAtIsNil(), oauthappsecret.ExpiresAtGT(time.Now())),
		).
		Order(ent.Desc(oauthappsecret.FieldCreatedAt), ent.Desc(oauthappsecret.FieldID)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("load client secrets: %w", err)
	}
	hashes := make([]string, 0, len(secrets))
	for _, sec := range secrets {
		hashes = append(hashes, sec.SecretHash)
	}
	return hashes, nil
}
