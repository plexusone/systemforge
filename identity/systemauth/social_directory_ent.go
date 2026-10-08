package systemauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/externalidentity"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/principal"
)

// EntPrincipalDirectory implements PrincipalDirectory on the Ent identity
// schema: Principal (type=human) + Human extension + ExternalIdentity link.
type EntPrincipalDirectory struct {
	db *ent.Client
}

// NewEntPrincipalDirectory creates an Ent-backed PrincipalDirectory.
func NewEntPrincipalDirectory(db *ent.Client) *EntPrincipalDirectory {
	return &EntPrincipalDirectory{db: db}
}

var _ PrincipalDirectory = (*EntPrincipalDirectory)(nil)

// FindByExternalIdentity implements PrincipalDirectory.
func (d *EntPrincipalDirectory) FindByExternalIdentity(ctx context.Context, provider, subject string) (*HumanPrincipal, error) {
	p, err := d.db.Principal.Query().
		Where(principal.HasExternalIdentitiesWith(
			externalidentity.ProviderEQ(provider),
			externalidentity.SubjectEQ(subject),
		)).
		WithHuman().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrPrincipalNotFound
		}
		return nil, err
	}
	return toHumanPrincipal(p), nil
}

// FindByVerifiedEmail implements PrincipalDirectory.
func (d *EntPrincipalDirectory) FindByVerifiedEmail(ctx context.Context, email string) (*HumanPrincipal, error) {
	p, err := d.db.Principal.Query().
		Where(
			principal.TypeEQ(principal.TypeHuman),
			principal.HasHumanWith(
				human.EmailEqualFold(email),
				human.EmailVerifiedAtNotNil(),
			),
		).
		WithHuman().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrPrincipalNotFound
		}
		return nil, err
	}
	return toHumanPrincipal(p), nil
}

// CreateFromExternal implements PrincipalDirectory.
func (d *EntPrincipalDirectory) CreateFromExternal(ctx context.Context, login ExternalLogin) (*HumanPrincipal, error) {
	tx, err := d.db.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %w", err)
	}

	p, err := d.createInTx(ctx, tx, login)
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return nil, errors.Join(err, fmt.Errorf("rolling back: %w", rbErr))
		}
		// Classify only after the transaction is closed so the follow-up
		// read does not contend with the failed transaction's locks.
		return nil, d.classifyCreateError(ctx, login, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, d.classifyCreateError(ctx, login, fmt.Errorf("committing: %w", err))
	}
	return p, nil
}

func (d *EntPrincipalDirectory) createInTx(ctx context.Context, tx *ent.Tx, login ExternalLogin) (*HumanPrincipal, error) {
	now := time.Now()
	hp := &HumanPrincipal{
		Email:         login.Email,
		EmailVerified: true,
		DisplayName:   displayNameFor(login),
		AvatarURL:     login.AvatarURL,
		Active:        true,
	}
	if err := createHumanRows(ctx, tx, hp, &now, &now); err != nil {
		return nil, err
	}

	if _, err := tx.ExternalIdentity.Create().
		SetPrincipalID(hp.ID).
		SetProvider(login.Provider).
		SetSubject(login.Subject).
		SetEmail(login.Email).
		SetEmailVerified(login.EmailVerified).
		SetLastLoginAt(now).
		Save(ctx); err != nil {
		return nil, fmt.Errorf("creating external identity: %w", err)
	}

	return hp, nil
}

// classifyCreateError maps unique-constraint failures to the sentinel the
// resolver expects. It must be called after the transaction has ended.
func (d *EntPrincipalDirectory) classifyCreateError(ctx context.Context, login ExternalLogin, err error) error {
	if !ent.IsConstraintError(err) {
		return err
	}
	linked, qerr := d.db.ExternalIdentity.Query().
		Where(
			externalidentity.ProviderEQ(login.Provider),
			externalidentity.SubjectEQ(login.Subject),
		).
		Exist(ctx)
	if qerr != nil {
		return errors.Join(err, qerr)
	}
	if linked {
		return ErrExternalIdentityExists
	}
	return fmt.Errorf("%w: %w", ErrEmailConflict, err)
}

// LinkExternalIdentity implements PrincipalDirectory.
func (d *EntPrincipalDirectory) LinkExternalIdentity(ctx context.Context, principalID uuid.UUID, login ExternalLogin) error {
	_, err := d.db.ExternalIdentity.Create().
		SetPrincipalID(principalID).
		SetProvider(login.Provider).
		SetSubject(login.Subject).
		SetEmail(login.Email).
		SetEmailVerified(login.EmailVerified).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return ErrExternalIdentityExists
		}
		return err
	}
	return nil
}

// RecordLogin implements PrincipalDirectory.
func (d *EntPrincipalDirectory) RecordLogin(ctx context.Context, principalID uuid.UUID, login ExternalLogin, at time.Time) error {
	if _, err := d.db.ExternalIdentity.Update().
		Where(
			externalidentity.ProviderEQ(login.Provider),
			externalidentity.SubjectEQ(login.Subject),
			externalidentity.PrincipalIDEQ(principalID),
		).
		SetEmail(login.Email).
		SetEmailVerified(login.EmailVerified).
		SetLastLoginAt(at).
		Save(ctx); err != nil {
		return fmt.Errorf("updating external identity: %w", err)
	}
	if _, err := d.db.Human.Update().
		Where(human.PrincipalIDEQ(principalID)).
		SetLastLoginAt(at).
		Save(ctx); err != nil {
		return fmt.Errorf("updating human: %w", err)
	}
	return nil
}

// GetPrincipal implements PrincipalDirectory.
func (d *EntPrincipalDirectory) GetPrincipal(ctx context.Context, id uuid.UUID) (*HumanPrincipal, error) {
	p, err := d.db.Principal.Query().
		Where(principal.IDEQ(id)).
		WithHuman().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrPrincipalNotFound
		}
		return nil, err
	}
	return toHumanPrincipal(p), nil
}
