package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/relyingparty"
)

// PrincipalStore is a relyingparty.PrincipalStore over the sf_rp_principals
// table, for applications that keep their principals in a plain table. It
// needs the table in SchemaSQL, created by EnsureSchema.
type PrincipalStore struct {
	db *sql.DB
}

var _ relyingparty.PrincipalStore = (*PrincipalStore)(nil)

// NewPrincipalStore returns a PrincipalStore over db.
func NewPrincipalStore(db *sql.DB) (*PrincipalStore, error) {
	if db == nil {
		return nil, errors.New("pgstore: a database is required")
	}
	return &PrincipalStore{db: db}, nil
}

const principalColumns = `id::text, coalesce(sf_principal_id, ''), type, coalesce(email, ''),
	email_verified, display_name, avatar_url, active, managed, created_at, updated_at`

func scanPrincipal(row *sql.Row) (*relyingparty.Principal, error) {
	var p relyingparty.Principal
	err := row.Scan(&p.ID, &p.SFPrincipalID, &p.Type, &p.Email, &p.EmailVerified,
		&p.Name, &p.AvatarURL, &p.Active, &p.Managed, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, relyingparty.ErrPrincipalNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pgstore: reading a principal: %w", err)
	}
	return &p, nil
}

// FindBySubject implements relyingparty.PrincipalStore.
func (s *PrincipalStore) FindBySubject(ctx context.Context, subject string) (*relyingparty.Principal, error) {
	if subject == "" {
		return nil, relyingparty.ErrPrincipalNotFound
	}
	return scanPrincipal(s.db.QueryRowContext(ctx,
		`SELECT `+principalColumns+` FROM sf_rp_principals WHERE sf_principal_id = $1`, subject))
}

// FindByEmail implements relyingparty.PrincipalStore. The match ignores
// case.
func (s *PrincipalStore) FindByEmail(ctx context.Context, email string) (*relyingparty.Principal, error) {
	if email == "" {
		return nil, relyingparty.ErrPrincipalNotFound
	}
	return scanPrincipal(s.db.QueryRowContext(ctx,
		`SELECT `+principalColumns+` FROM sf_rp_principals WHERE email IS NOT NULL AND lower(email) = lower($1)`, email))
}

// GetPrincipal implements relyingparty.PrincipalStore.
func (s *PrincipalStore) GetPrincipal(ctx context.Context, id string) (*relyingparty.Principal, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, relyingparty.ErrPrincipalNotFound
	}
	return scanPrincipal(s.db.QueryRowContext(ctx,
		`SELECT `+principalColumns+` FROM sf_rp_principals WHERE id = $1`, uid))
}

// LinkSubject implements relyingparty.PrincipalStore.
func (s *PrincipalStore) LinkSubject(ctx context.Context, principalID, subject string) error {
	uid, err := uuid.Parse(principalID)
	if err != nil {
		return relyingparty.ErrPrincipalNotFound
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE sf_rp_principals SET sf_principal_id = $2, updated_at = now() WHERE id = $1`, uid, subject)
	if isUniqueViolation(err) {
		return relyingparty.ErrSubjectLinked
	}
	if err != nil {
		return fmt.Errorf("pgstore: linking a subject: %w", err)
	}
	return oneRow(res)
}

// CreatePrincipal implements relyingparty.PrincipalStore: an active human
// principal linked to the identity's subject. An identity without an email
// (a managed principal) is stored without one.
func (s *PrincipalStore) CreatePrincipal(ctx context.Context, id relyingparty.VerifiedIdentity) (*relyingparty.Principal, error) {
	name := id.Name
	if name == "" {
		name = id.Email
	}
	var email sql.NullString
	if id.Email != "" {
		email = sql.NullString{String: id.Email, Valid: true}
	}
	verified := id.Email != "" && (id.EmailVerified || !id.Managed)
	// ON CONFLICT DO NOTHING covers both unique indexes, so a conflict is
	// told apart afterwards without depending on driver error types.
	p, err := scanPrincipal(s.db.QueryRowContext(ctx, `
		INSERT INTO sf_rp_principals
			(id, sf_principal_id, type, email, email_verified, display_name, avatar_url, managed)
		VALUES ($1, $2, 'human', $3, $4, $5, $6, $7)
		ON CONFLICT DO NOTHING
		RETURNING `+principalColumns,
		uuid.New(), id.Subject, email, verified, name, id.Picture, id.Managed))
	if errors.Is(err, relyingparty.ErrPrincipalNotFound) {
		return nil, s.conflict(ctx, id)
	}
	return p, err
}

// conflict names the constraint a refused insert ran into.
func (s *PrincipalStore) conflict(ctx context.Context, id relyingparty.VerifiedIdentity) error {
	_, err := s.FindBySubject(ctx, id.Subject)
	switch {
	case err == nil:
		return relyingparty.ErrSubjectLinked
	case !errors.Is(err, relyingparty.ErrPrincipalNotFound):
		return err
	}
	if id.Email != "" {
		return relyingparty.ErrEmailConflict
	}
	// Neither index matches now: the conflicting row was removed after the
	// insert was refused. Report the subject, which makes ResolvePrincipal
	// try again.
	return relyingparty.ErrSubjectLinked
}

// RecordLogin implements relyingparty.PrincipalStore: it refreshes the
// name and avatar when the identity carries them, and the last sign-in time.
func (s *PrincipalStore) RecordLogin(ctx context.Context, principalID string, id relyingparty.VerifiedIdentity, at time.Time) error {
	uid, err := uuid.Parse(principalID)
	if err != nil {
		return relyingparty.ErrPrincipalNotFound
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE sf_rp_principals SET
			display_name = CASE WHEN $2::text = '' THEN display_name ELSE $2::text END,
			avatar_url   = CASE WHEN $3::text = '' THEN avatar_url ELSE $3::text END,
			last_login_at = $4,
			updated_at = now()
		WHERE id = $1`, uid, id.Name, id.Picture, at)
	if err != nil {
		return fmt.Errorf("pgstore: recording a sign-in: %w", err)
	}
	return oneRow(res)
}

// SetActive enables or disables a principal. relyingparty refuses an
// inactive principal at sign-in and on every request.
func (s *PrincipalStore) SetActive(ctx context.Context, principalID string, active bool) error {
	uid, err := uuid.Parse(principalID)
	if err != nil {
		return relyingparty.ErrPrincipalNotFound
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE sf_rp_principals SET active = $2, updated_at = now() WHERE id = $1`, uid, active)
	if err != nil {
		return fmt.Errorf("pgstore: setting a principal active: %w", err)
	}
	return oneRow(res)
}

// Delete removes a principal. The application removes or reassigns its own
// rows that refer to it first.
func (s *PrincipalStore) Delete(ctx context.Context, principalID string) error {
	uid, err := uuid.Parse(principalID)
	if err != nil {
		return relyingparty.ErrPrincipalNotFound
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM sf_rp_principals WHERE id = $1`, uid)
	if err != nil {
		return fmt.Errorf("pgstore: deleting a principal: %w", err)
	}
	return oneRow(res)
}

// oneRow maps an update that matched no row to ErrPrincipalNotFound.
func oneRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("pgstore: counting affected rows: %w", err)
	}
	if n == 0 {
		return relyingparty.ErrPrincipalNotFound
	}
	return nil
}

// isUniqueViolation reports a PostgreSQL unique_violation (SQLSTATE 23505)
// from any driver whose errors report their SQLSTATE.
func isUniqueViolation(err error) bool {
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		return state.SQLState() == "23505"
	}
	return err != nil && strings.Contains(err.Error(), "SQLSTATE 23505")
}
