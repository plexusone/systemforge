package systemauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/principal"
)

// ErrEmailChangeStale is returned by PrincipalEmailChanger.ChangeEmail when
// the principal's email is no longer the one the change was requested
// from.
var ErrEmailChangeStale = errors.New("systemauth: the email changed since the change was requested")

// PrincipalEmailChanger is implemented by principal directories that can
// change a principal's email. SystemAuth's email change (ADR-003) calls it
// only after the new address is proven.
type PrincipalEmailChanger interface {
	// ChangeEmail replaces the principal's email from with to, marked
	// verified at verifiedAt. It returns ErrPrincipalNotFound,
	// ErrEmailChangeStale when the current email is not from (ignoring
	// case), or ErrEmailConflict when another principal has to.
	ChangeEmail(ctx context.Context, principalID uuid.UUID, from, to string, verifiedAt time.Time) error
}

var (
	_ PrincipalEmailChanger = (*EntPrincipalDirectory)(nil)
	_ PrincipalEmailChanger = (*MemoryPrincipalDirectory)(nil)
	_ PrincipalEmailChanger = memoryStorageDirectory{}
)

// ChangeEmail implements PrincipalEmailChanger. The human's email, its
// verification time and the principal's identifier change in one
// transaction.
func (d *EntPrincipalDirectory) ChangeEmail(ctx context.Context, principalID uuid.UUID, from, to string, verifiedAt time.Time) error {
	tx, err := d.db.Tx(ctx)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	if err := changeEmailInTx(ctx, tx, principalID, from, to, verifiedAt); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return errors.Join(err, fmt.Errorf("rolling back: %w", rbErr))
		}
		if ent.IsConstraintError(err) {
			return fmt.Errorf("%w: %w", ErrEmailConflict, err)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		if ent.IsConstraintError(err) {
			return fmt.Errorf("%w: %w", ErrEmailConflict, err)
		}
		return fmt.Errorf("committing: %w", err)
	}
	return nil
}

func changeEmailInTx(ctx context.Context, tx *ent.Tx, principalID uuid.UUID, from, to string, verifiedAt time.Time) error {
	h, err := tx.Human.Query().
		Where(human.PrincipalIDEQ(principalID), human.HasPrincipalWith(principal.TypeEQ(principal.TypeHuman))).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return ErrPrincipalNotFound
		}
		return err
	}
	if h.Email == nil || !strings.EqualFold(*h.Email, from) {
		return ErrEmailChangeStale
	}
	taken, err := emailTakenInTx(ctx, tx, to, principalID)
	if err != nil {
		return err
	}
	if taken {
		return ErrEmailConflict
	}
	if _, err := tx.Human.UpdateOne(h).SetEmail(to).SetEmailVerifiedAt(verifiedAt).Save(ctx); err != nil {
		return err
	}
	_, err = tx.Principal.UpdateOneID(principalID).SetIdentifier(to).Save(ctx)
	return err
}

// ChangeEmail implements PrincipalEmailChanger.
func (d *MemoryPrincipalDirectory) ChangeEmail(_ context.Context, principalID uuid.UUID, from, to string, verifiedAt time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.principals[principalID]
	if !ok {
		return ErrPrincipalNotFound
	}
	if p.Email == "" || !strings.EqualFold(p.Email, from) {
		return ErrEmailChangeStale
	}
	key := strings.ToLower(to)
	if id, taken := d.byEmail[key]; taken && id != principalID {
		return ErrEmailConflict
	}
	delete(d.byEmail, strings.ToLower(p.Email))
	p.Email, p.EmailVerified, p.EmailVerifiedAt = to, true, verifiedAt
	d.byEmail[key] = principalID
	return nil
}

// ChangeEmail implements PrincipalEmailChanger.
func (d memoryStorageDirectory) ChangeEmail(_ context.Context, principalID uuid.UUID, from, to string, verifiedAt time.Time) error {
	d.s.mu.Lock()
	defer d.s.mu.Unlock()
	h, ok := d.s.humans[principalID]
	if !ok {
		return ErrPrincipalNotFound
	}
	if h.Email == "" || !strings.EqualFold(h.Email, from) {
		return ErrEmailChangeStale
	}
	if other, taken := d.s.humanByEmailLocked(to); taken && other.ID != principalID {
		return ErrEmailConflict
	}
	h.Email, h.EmailVerified, h.EmailVerifiedAt, h.UpdatedAt = to, true, verifiedAt, time.Now()
	return nil
}
