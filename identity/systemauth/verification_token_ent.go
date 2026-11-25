package systemauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/predicate"
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

// ConsumeToken implements VerificationTokenStore.
func (s *EntVerificationTokenStore) ConsumeToken(ctx context.Context, id uuid.UUID, purpose VerificationPurpose, binding string) error {
	if binding == "" || !purpose.Valid() {
		return ErrVerificationTokenInvalid
	}
	row, err := s.db.VerificationToken.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrVerificationTokenInvalid
		}
		return fmt.Errorf("reading verification token: %w", err)
	}
	now := s.now()
	// Whether a newer token exists is part of the update, not a read before
	// it: a replacement stored between a check and the mark would otherwise
	// be missed. A replacement stored after the mark is a later sign-in's.
	n, err := s.db.VerificationToken.Update().
		Where(
			verificationtoken.IDEQ(id),
			verificationtoken.PurposeEQ(verificationtoken.Purpose(purpose)),
			verificationtoken.BindingEQ(binding),
			verificationtoken.ConsumedAtIsNil(),
			verificationtoken.ExpiresAtGT(now),
			noNewerToken(row),
		).
		SetConsumedAt(now).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("consuming verification token: %w", err)
	}
	if n != 1 {
		return ErrVerificationTokenInvalid
	}
	return nil
}

// noNewerToken matches rows for which no token of the same purpose and
// binding was issued later, or at the same time with a greater ID, the
// order Latest uses.
func noNewerToken(row *ent.VerificationToken) predicate.VerificationToken {
	return func(s *sql.Selector) {
		newer := sql.Table(verificationtoken.Table).As("newer")
		s.Where(sql.NotExists(sql.Select(newer.C(verificationtoken.FieldID)).From(newer).Where(sql.And(
			sql.EQ(newer.C(verificationtoken.FieldPurpose), string(row.Purpose)),
			sql.EQ(newer.C(verificationtoken.FieldBinding), row.Binding),
			sql.Or(
				sql.GT(newer.C(verificationtoken.FieldCreatedAt), row.CreatedAt),
				sql.And(
					sql.EQ(newer.C(verificationtoken.FieldCreatedAt), row.CreatedAt),
					sql.GT(newer.C(verificationtoken.FieldID), row.ID),
				),
			),
		))))
	}
}

// RecordAttempt implements VerificationTokenStore.
func (s *EntVerificationTokenStore) RecordAttempt(ctx context.Context, purpose VerificationPurpose, binding string, limit int) (*VerificationToken, error) {
	if limit < 1 || !purpose.Valid() || binding == "" {
		return nil, ErrVerificationTokenInvalid
	}
	latest, err := s.Latest(ctx, purpose, binding)
	if err != nil {
		if errors.Is(err, ErrVerificationTokenNotFound) {
			return nil, ErrVerificationTokenInvalid
		}
		return nil, err
	}
	// The limit and the count are one statement: of concurrent guesses
	// only those whose update matched while attempts were below limit are
	// counted, so the limit holds across instances. A token consumed or
	// expired since Latest matches nothing. The count handed back is read in
	// the same transaction: the update holds the row until the commit, so the
	// value read is this call's own increment, never another call's.
	tx, err := s.db.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %w", err)
	}
	n, err := tx.VerificationToken.Update().
		Where(
			verificationtoken.IDEQ(latest.ID),
			verificationtoken.AttemptsLT(limit),
			verificationtoken.ConsumedAtIsNil(),
			verificationtoken.ExpiresAtGT(s.now()),
		).
		AddAttempts(1).
		Save(ctx)
	if err != nil {
		return nil, rollbackWith(tx, fmt.Errorf("counting verification attempt: %w", err))
	}
	if n != 1 {
		return nil, rollbackWith(tx, ErrVerificationTokenInvalid)
	}
	row, err := tx.VerificationToken.Get(ctx, latest.ID)
	if err != nil {
		return nil, rollbackWith(tx, fmt.Errorf("reading verification token: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing verification attempt: %w", err)
	}
	return toVerificationToken(row), nil
}

// rollbackWith rolls tx back and returns err, joined with the rollback's own
// error when that fails too.
func rollbackWith(tx *ent.Tx, err error) error {
	if rbErr := tx.Rollback(); rbErr != nil {
		return errors.Join(err, fmt.Errorf("rolling back: %w", rbErr))
	}
	return err
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
		Attempts:   row.Attempts,
		ConsumedAt: row.ConsumedAt,
	}
	if row.PrincipalID != nil {
		t.PrincipalID = *row.PrincipalID
	}
	return t
}

var _ VerificationTokenStore = (*EntVerificationTokenStore)(nil)
