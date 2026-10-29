package systemauth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/verificationtoken"
)

// EntVerificationTokenStore is a VerificationTokenStore backed by the
// sf_verification_tokens table. Only token hashes are stored. Consume is a
// single conditional update, so a token is used once across every instance
// sharing the database.
type EntVerificationTokenStore struct {
	db   *ent.Client
	now  func() time.Time
	gate *cleanupGate
}

// NewEntVerificationTokenStore creates a verification token store on
// client. Expired rows are deleted opportunistically while tokens are
// created (WithCleanupInterval), or by calling DeleteExpired.
func NewEntVerificationTokenStore(client *ent.Client, opts ...EntStoreOption) *EntVerificationTokenStore {
	c := newEntStoreConfig(opts)
	return &EntVerificationTokenStore{db: client, now: c.now, gate: &cleanupGate{interval: c.cleanupInterval}}
}

// Create implements VerificationTokenStore.
func (s *EntVerificationTokenStore) Create(ctx context.Context, token string, t VerificationToken) error {
	now := s.now()
	if err := prepareVerificationToken(token, &t, now); err != nil {
		return err
	}
	maybeCleanup(ctx, s.gate, now, "verification_tokens", s.DeleteExpired)
	c := s.db.VerificationToken.Create().
		SetID(t.ID).
		SetTokenHash(hashSessionToken(token)).
		SetPurpose(verificationtoken.Purpose(t.Purpose)).
		SetEmail(t.Email).
		SetBinding(t.Binding).
		SetCreatedAt(t.CreatedAt.UTC()).
		SetExpiresAt(t.ExpiresAt.UTC())
	if t.PrincipalID != uuid.Nil {
		c.SetPrincipalID(t.PrincipalID)
	}
	if len(t.Data) > 0 {
		c.SetData(t.Data)
	}
	if err := c.Exec(ctx); err != nil {
		return fmt.Errorf("storing verification token: %w", err)
	}
	return nil
}

// Consume implements VerificationTokenStore.
func (s *EntVerificationTokenStore) Consume(ctx context.Context, token string, purpose VerificationPurpose, binding string) (*VerificationToken, error) {
	if token == "" || binding == "" || !purpose.Valid() {
		return nil, ErrVerificationTokenInvalid
	}
	now := s.now()
	hash := hashSessionToken(token)
	// The conditions and the mark are one statement: of concurrent
	// consumers only the one whose update matched the row may use it, and
	// a request with the wrong purpose or binding matches nothing and
	// leaves the token usable for its owner.
	n, err := s.db.VerificationToken.Update().
		Where(
			verificationtoken.TokenHashEQ(hash),
			verificationtoken.PurposeEQ(verificationtoken.Purpose(purpose)),
			verificationtoken.BindingEQ(binding),
			verificationtoken.ConsumedAtIsNil(),
			verificationtoken.ExpiresAtGT(now),
		).
		SetConsumedAt(now).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("consuming verification token: %w", err)
	}
	if n != 1 {
		return nil, ErrVerificationTokenInvalid
	}
	row, err := s.db.VerificationToken.Query().Where(verificationtoken.TokenHashEQ(hash)).Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading consumed verification token: %w", err)
	}
	return toVerificationToken(row), nil
}

// Latest implements VerificationTokenStore.
func (s *EntVerificationTokenStore) Latest(ctx context.Context, purpose VerificationPurpose, binding string) (*VerificationToken, error) {
	if !purpose.Valid() || binding == "" {
		return nil, ErrVerificationTokenNotFound
	}
	row, err := s.db.VerificationToken.Query().
		Where(
			verificationtoken.PurposeEQ(verificationtoken.Purpose(purpose)),
			verificationtoken.BindingEQ(binding),
			verificationtoken.ConsumedAtIsNil(),
			verificationtoken.ExpiresAtGT(s.now()),
		).
		Order(ent.Desc(verificationtoken.FieldCreatedAt), ent.Desc(verificationtoken.FieldID)).
		First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrVerificationTokenNotFound
		}
		return nil, fmt.Errorf("reading verification token: %w", err)
	}
	return toVerificationToken(row), nil
}

// Revoke implements VerificationTokenStore.
func (s *EntVerificationTokenStore) Revoke(ctx context.Context, purpose VerificationPurpose, binding string) (int, error) {
	if !purpose.Valid() || binding == "" {
		return 0, nil
	}
	now := s.now()
	n, err := s.db.VerificationToken.Update().
		Where(
			verificationtoken.PurposeEQ(verificationtoken.Purpose(purpose)),
			verificationtoken.BindingEQ(binding),
			verificationtoken.ConsumedAtIsNil(),
			verificationtoken.ExpiresAtGT(now),
		).
		SetConsumedAt(now).
		Save(ctx)
	if err != nil {
		return 0, fmt.Errorf("revoking verification tokens: %w", err)
	}
	return n, nil
}

// DeleteExpired implements VerificationTokenStore.
func (s *EntVerificationTokenStore) DeleteExpired(ctx context.Context) (int, error) {
	n, err := s.db.VerificationToken.Delete().
		Where(verificationtoken.ExpiresAtLTE(s.now())).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("deleting expired verification tokens: %w", err)
	}
	return n, nil
}

func toVerificationToken(row *ent.VerificationToken) *VerificationToken {
	t := &VerificationToken{
		ID:         row.ID,
		Purpose:    VerificationPurpose(row.Purpose),
		Email:      row.Email,
		Binding:    row.Binding,
		Data:       row.Data,
		CreatedAt:  row.CreatedAt,
		ExpiresAt:  row.ExpiresAt,
		ConsumedAt: row.ConsumedAt,
	}
	if row.PrincipalID != nil {
		t.PrincipalID = *row.PrincipalID
	}
	return t
}

var _ VerificationTokenStore = (*EntVerificationTokenStore)(nil)
