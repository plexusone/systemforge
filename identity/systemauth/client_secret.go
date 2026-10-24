package systemauth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"

	"github.com/plexusone/systemforge/identity"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/oauthapp"
	"github.com/plexusone/systemforge/identity/ent/oauthappsecret"
)

// MaxActiveClientSecrets is how many of a client's secrets authenticate at
// once: the current secret (N) and the one it replaced (N-1), so a
// rotation always leaves a known working secret to fall back to. Older
// secrets (N-2 and earlier) are not accepted even when they have not been
// revoked, and RotateClientSecret revokes them.
const MaxActiveClientSecrets = 2

// argon2idPrefix marks an Argon2id hash in the PHC string format written by
// identity.HashPassword.
const argon2idPrefix = "$argon2id$"

// ErrClientSecretNotFound is returned when a client secret to revoke does
// not exist for the client.
var ErrClientSecretNotFound = errors.New("systemauth: client secret not found")

// ErrPublicClient is returned when a secret operation is requested for a
// public client, which has no secrets.
var ErrPublicClient = errors.New("systemauth: public clients have no secret")

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
// authenticates with, newest first: at most MaxActiveClientSecrets that are
// neither revoked nor expired.
func ActiveClientSecretHashes(ctx context.Context, db *ent.Client, appID uuid.UUID) ([]string, error) {
	secrets, err := db.OAuthAppSecret.Query().
		Where(
			oauthappsecret.AppIDEQ(appID),
			oauthappsecret.RevokedEQ(false),
			oauthappsecret.Or(oauthappsecret.ExpiresAtIsNil(), oauthappsecret.ExpiresAtGT(time.Now())),
		).
		Order(ent.Desc(oauthappsecret.FieldCreatedAt), ent.Desc(oauthappsecret.FieldID)).
		Limit(MaxActiveClientSecrets).
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

// RotatedClientSecret is a client secret issued by RotateClientSecret. The
// plaintext Secret is returned only here.
type RotatedClientSecret struct {
	// ID identifies the secret, for RevokeClientSecret.
	ID uuid.UUID
	// Secret is the new plaintext client secret.
	Secret string
	// Prefix is the stored, displayable prefix of the secret.
	Prefix string
}

// RotateClientSecret issues a new secret for a confidential client. The
// new secret (N) becomes the client's current secret and the one it
// replaces (N-1) keeps working, so clients can move over and a rollback to
// N-1 stays possible; secrets older than that (N-2 and earlier) are
// revoked. Revoke N-1 with RevokeClientSecret to end the overlap early.
func (s *EntStorage) RotateClientSecret(ctx context.Context, clientID string) (*RotatedClientSecret, error) {
	app, err := s.db.OAuthApp.Query().Where(oauthapp.ClientIDEQ(clientID), oauthapp.ActiveEQ(true)).Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("rotate client secret: %w", err)
	}
	if app.Public {
		return nil, ErrPublicClient
	}
	secret := rand.Text()
	hash, err := ClientSecretHasher{}.Hash(ctx, []byte(secret))
	if err != nil {
		return nil, fmt.Errorf("rotate client secret: hash: %w", err)
	}
	prefix := secret[:8]

	tx, err := s.db.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("rotate client secret: %w", err)
	}
	created, err := rotateSecretTx(ctx, tx, app.ID, string(hash), prefix)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("rotate client secret: %w", err), tx.Rollback())
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("rotate client secret: commit: %w", err)
	}
	return &RotatedClientSecret{ID: created.ID, Secret: secret, Prefix: prefix}, nil
}

// rotateSecretTx keeps the newest active secret as N-1, revokes every
// other active secret, and stores the new one.
func rotateSecretTx(ctx context.Context, tx *ent.Tx, appID uuid.UUID, hash, prefix string) (*ent.OAuthAppSecret, error) {
	active, err := tx.OAuthAppSecret.Query().
		Where(oauthappsecret.AppIDEQ(appID), oauthappsecret.RevokedEQ(false)).
		Order(ent.Desc(oauthappsecret.FieldCreatedAt), ent.Desc(oauthappsecret.FieldID)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var stale []uuid.UUID
	keptPrevious := false
	for _, sec := range active {
		if !keptPrevious && (sec.ExpiresAt == nil || sec.ExpiresAt.After(now)) {
			keptPrevious = true
			continue
		}
		stale = append(stale, sec.ID)
	}
	if len(stale) > 0 {
		if err := tx.OAuthAppSecret.Update().
			Where(oauthappsecret.IDIn(stale...)).
			SetRevoked(true).
			SetRevokedAt(now).
			Exec(ctx); err != nil {
			return nil, err
		}
	}
	// The new secret must sort after N-1 even when the clock has not moved.
	created := now
	if len(active) > 0 && !active[0].CreatedAt.Before(created) {
		created = active[0].CreatedAt.Add(time.Microsecond)
	}
	return tx.OAuthAppSecret.Create().
		SetAppID(appID).
		SetSecretHash(hash).
		SetSecretPrefix(prefix).
		SetCreatedAt(created).
		Save(ctx)
}

// RevokeClientSecret revokes one of a client's secrets, for example the
// previous secret once every caller uses the new one, or a new secret that
// turned out to be bad, so the previous one is current again.
func (s *EntStorage) RevokeClientSecret(ctx context.Context, clientID string, secretID uuid.UUID) error {
	n, err := s.db.OAuthAppSecret.Update().
		Where(
			oauthappsecret.IDEQ(secretID),
			oauthappsecret.RevokedEQ(false),
			oauthappsecret.HasAppWith(oauthapp.ClientIDEQ(clientID)),
		).
		SetRevoked(true).
		SetRevokedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("revoke client secret: %w", err)
	}
	if n == 0 {
		return ErrClientSecretNotFound
	}
	return nil
}
