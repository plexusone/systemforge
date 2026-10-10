package systemauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/externalidentity"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/signup"
)

// EntPrincipalDirectory implements PrincipalDirectory on the Ent identity
// schema: Principal (type=human) + Human extension + ExternalIdentity link.
type EntPrincipalDirectory struct {
	db       *ent.Client
	syncer   authz.RelationshipSyncer
	syncMode authz.SyncMode
	logger   *slog.Logger
}

// EntPrincipalDirectoryOption configures an EntPrincipalDirectory.
type EntPrincipalDirectoryOption func(*EntPrincipalDirectory)

// WithDirectoryAuthzSyncer sets the authorization syncer that registers the
// principals and personal organizations the directory creates, so they exist
// in relationship-based authorization. Registration runs after the creating
// transaction commits.
func WithDirectoryAuthzSyncer(syncer authz.RelationshipSyncer) EntPrincipalDirectoryOption {
	return func(d *EntPrincipalDirectory) { d.syncer = syncer }
}

// WithDirectorySyncMode sets the sync mode: in strict mode a failed
// registration is returned (the rows stay committed), in eventual mode
// (the default) it is logged.
func WithDirectorySyncMode(mode authz.SyncMode) EntPrincipalDirectoryOption {
	return func(d *EntPrincipalDirectory) { d.syncMode = mode }
}

// WithDirectoryLogger sets the logger used for tolerated sync failures.
func WithDirectoryLogger(logger *slog.Logger) EntPrincipalDirectoryOption {
	return func(d *EntPrincipalDirectory) { d.logger = logger }
}

// NewEntPrincipalDirectory creates an Ent-backed PrincipalDirectory. Without
// a syncer option, nothing is registered with an authorization backend.
func NewEntPrincipalDirectory(db *ent.Client, opts ...EntPrincipalDirectoryOption) *EntPrincipalDirectory {
	d := &EntPrincipalDirectory{
		db:       db,
		syncer:   noop.NewSyncer(),
		syncMode: authz.SyncModeEventual,
		logger:   slog.Default(),
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// syncOrg registers a personal organization and its owner with the
// authorization syncer. It must be called after the transaction committed.
func (d *EntPrincipalDirectory) syncOrg(ctx context.Context, org *signup.PersonalOrg) error {
	if err := d.syncer.RegisterOrganization(ctx, org.Organization.ID, *org.Organization.OwnerPrincipalID); err != nil {
		if d.syncMode == authz.SyncModeStrict {
			return fmt.Errorf("failed to sync organization to authz: %w", err)
		}
		d.logger.Warn("failed to sync organization to authz", "org_id", org.Organization.ID, "error", err)
	}
	return nil
}

var (
	_ PrincipalDirectory = (*EntPrincipalDirectory)(nil)
	_ PersonalOrgEnsurer = (*EntPrincipalDirectory)(nil)
)

// FindByExternalIdentity implements PrincipalDirectory.
func (d *EntPrincipalDirectory) FindByExternalIdentity(ctx context.Context, provider, subject string) (*HumanPrincipal, error) {
	p, err := d.db.Principal.Query().
		Where(principal.HasExternalIdentitiesWith(
			externalidentity.ProviderEQ(provider),
			externalidentity.SubjectEQ(subject),
		)).
		WithHuman().
		WithManagers(activeManagers).
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
		WithManagers(activeManagers).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrPrincipalNotFound
		}
		return nil, err
	}
	return toHumanPrincipal(p), nil
}

// createAttempts bounds retries of a first login that loses a race for the
// personal organization's slug to another transaction.
const createAttempts = 3

// errCreateRace marks a create that failed on a constraint other than the
// external identity or the email, i.e. a lost race for a slug; retrying the
// whole transaction picks the next free slug.
var errCreateRace = errors.New("systemauth: lost a race creating the principal")

// CreateFromExternal implements PrincipalDirectory. The principal, its
// human row, the external identity, the personal organization and the owner
// membership are written in one transaction: a failure at any step leaves
// nothing behind.
func (d *EntPrincipalDirectory) CreateFromExternal(ctx context.Context, login ExternalLogin) (*HumanPrincipal, error) {
	var lastErr error
	for attempt := 0; attempt < createAttempts; attempt++ {
		p, err := d.createOnce(ctx, login)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, errCreateRace) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

func (d *EntPrincipalDirectory) createOnce(ctx context.Context, login ExternalLogin) (*HumanPrincipal, error) {
	tx, err := d.db.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("starting transaction: %w", err)
	}

	p, org, err := d.createInTx(ctx, tx, login)
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

	// Register with the authorization backend only after the rows are
	// durable, so a rolled-back signup never leaves graph entries behind.
	if syncErr := d.syncer.RegisterPrincipal(ctx, p.ID); syncErr != nil {
		if d.syncMode == authz.SyncModeStrict {
			return nil, fmt.Errorf("failed to sync principal to authz: %w", syncErr)
		}
		d.logger.Warn("failed to sync principal to authz", "principal_id", p.ID, "error", syncErr)
	}
	if err := d.syncOrg(ctx, org); err != nil {
		return nil, err
	}
	return p, nil
}

func (d *EntPrincipalDirectory) createInTx(ctx context.Context, tx *ent.Tx, login ExternalLogin) (*HumanPrincipal, *signup.PersonalOrg, error) {
	now := time.Now()
	hp := &HumanPrincipal{
		Email:         login.Email,
		EmailVerified: true,
		DisplayName:   displayNameFor(login),
		AvatarURL:     login.AvatarURL,
		Active:        true,
	}
	if err := createHumanRows(ctx, tx, hp, &now, &now); err != nil {
		return nil, nil, err
	}

	if _, err := tx.ExternalIdentity.Create().
		SetPrincipalID(hp.ID).
		SetProvider(login.Provider).
		SetSubject(login.Subject).
		SetEmail(login.Email).
		SetEmailVerified(login.EmailVerified).
		SetLastLoginAt(now).
		Save(ctx); err != nil {
		return nil, nil, fmt.Errorf("creating external identity: %w", err)
	}

	org, err := signup.CreatePersonalOrgInTx(ctx, tx, personalOrgParams(hp.ID, login))
	if err != nil {
		return nil, nil, err
	}
	return hp, org, nil
}

// managedPersonalOrgParams builds the personal organization of a managed
// principal that signs in with an email of its own (ADR-009). Nothing in it
// comes from the login: a handle derived from the email's local part or a
// provider username would expose a managed person's address, so the slug is
// the generated, address-free form and the name is the one its managers
// gave.
func managedPersonalOrgParams(p *HumanPrincipal) signup.PersonalOrgParams {
	slug := signup.SlugForManaged("")
	name := p.DisplayName
	if name == "" {
		name = slug
	}
	return signup.PersonalOrgParams{OwnerID: p.ID, Name: name, Slug: slug}
}

// personalOrgParamsFor picks the personal organization parameters for a
// principal: the generated form for a managed principal, otherwise the
// login's.
func personalOrgParamsFor(p *HumanPrincipal, login ExternalLogin) signup.PersonalOrgParams {
	if p.Managed {
		return managedPersonalOrgParams(p)
	}
	return personalOrgParams(p.ID, login)
}

// personalOrgParams builds the personal organization for a login: named for
// the person (display name, else provider handle, else email local part),
// slugged by signup.SlugForLogin.
func personalOrgParams(ownerID uuid.UUID, login ExternalLogin) signup.PersonalOrgParams {
	name := login.Name
	if name == "" {
		name = login.Username
	}
	if name == "" {
		name, _, _ = strings.Cut(login.Email, "@")
	}
	if name == "" {
		name = displayNameFor(login)
	}
	return signup.PersonalOrgParams{
		OwnerID: ownerID,
		Name:    name,
		Slug:    signup.SlugForLogin(login.Provider, login.Username, login.Email),
		LogoURL: login.AvatarURL,
	}
}

// EnsurePersonalOrg implements PersonalOrgEnsurer. It runs in its own
// transaction and is a no-op for a principal that already has a personal
// organization.
func (d *EntPrincipalDirectory) EnsurePersonalOrg(ctx context.Context, p *HumanPrincipal, login ExternalLogin) error {
	for attempt := 0; attempt < createAttempts; attempt++ {
		err := d.ensureOnce(ctx, p, login)
		if err == nil || !ent.IsConstraintError(err) {
			return err
		}
	}
	return fmt.Errorf("creating personal organization: slug contention after %d attempts", createAttempts)
}

func (d *EntPrincipalDirectory) ensureOnce(ctx context.Context, p *HumanPrincipal, login ExternalLogin) error {
	tx, err := d.db.Tx(ctx)
	if err != nil {
		return fmt.Errorf("starting transaction: %w", err)
	}
	org, created, err := signup.EnsurePersonalOrgInTx(ctx, tx, personalOrgParamsFor(p, login))
	if err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return errors.Join(err, fmt.Errorf("rolling back: %w", rbErr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing: %w", err)
	}
	if created {
		return d.syncOrg(ctx, org)
	}
	return nil
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
	taken, qerr := d.db.Human.Query().Where(human.EmailEqualFold(login.Email)).Exist(ctx)
	if qerr != nil {
		return errors.Join(err, qerr)
	}
	if taken {
		return fmt.Errorf("%w: %w", ErrEmailConflict, err)
	}
	return fmt.Errorf("%w: %w", errCreateRace, err)
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
		WithManagers(activeManagers).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, ErrPrincipalNotFound
		}
		return nil, err
	}
	return toHumanPrincipal(p), nil
}
