package signupgate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	"github.com/plexusone/systemforge/identity/ent/signupallowance"
	"github.com/plexusone/systemforge/identity/ent/signupcode"
)

// DefaultMemberCodeTTL is how long a member's invite code works when
// MemberOptions.CodeTTL is not set.
const DefaultMemberCodeTTL = 14 * 24 * time.Hour

// MemberOptions configure member invites.
type MemberOptions struct {
	// DefaultAllowance is how many invite codes a member may hold when an
	// operator has not set their allowance. The default is 0: members invite
	// nobody until an operator allows it.
	DefaultAllowance int
	// CodeTTL is how long a member's invite code works. Zero means
	// DefaultMemberCodeTTL.
	CodeTTL time.Duration
}

func (o MemberOptions) withDefaults() MemberOptions {
	if o.DefaultAllowance < 0 {
		o.DefaultAllowance = 0
	}
	if o.CodeTTL <= 0 {
		o.CodeTTL = DefaultMemberCodeTTL
	}
	return o
}

// ErrAllowanceExhausted means a member already holds as many invite codes
// as their allowance permits.
var ErrAllowanceExhausted = errors.New("signupgate: no invites left")

// ErrNoAccount means no account has the given email address.
var ErrNoAccount = errors.New("signupgate: no account with that email address")

// Allowance is a member's invite allowance as listed to operators.
type Allowance struct {
	PrincipalID uuid.UUID
	Email       string
	// Granted is the allowance an operator set; nil means the default.
	Granted *int
	// Effective is Granted, or the deployment's default when it is nil.
	Effective int
	// Held is how many of the member's codes count against it.
	Held      int
	Note      string
	SetBy     *uuid.UUID
	UpdatedAt time.Time
}

// MemberSummary is what a member sees of their own invites.
type MemberSummary struct {
	Allowance int
	Held      int
	Remaining int
	// Codes are the member's codes, newest first, whatever their status.
	Codes []Code
	// CodeTTL is how long a new member code works.
	CodeTTL time.Duration
}

// MemberOptions returns the member invite settings the store applies.
func (s *CodeStore) MemberOptions() MemberOptions { return s.member }

// held matches a member's codes that count against their allowance: used
// (or reserved), or still usable.
func held(principalID uuid.UUID, now time.Time) predicate.SignupCode {
	return signupcode.And(
		signupcode.KindEQ(signupcode.KindMember),
		signupcode.CreatedByPrincipalIDEQ(principalID),
		signupcode.Or(
			signupcode.UseCountGT(0),
			signupcode.And(
				signupcode.RevokedAtIsNil(),
				signupcode.Or(signupcode.ExpiresAtIsNil(), signupcode.ExpiresAtGT(now)),
			),
		),
	)
}

func (s *CodeStore) effective(granted *int) int {
	if granted == nil {
		return s.member.DefaultAllowance
	}
	return *granted
}

// SetAllowance sets how many invite codes a member may hold. A nil granted
// returns the member to the deployment's default.
func (s *CodeStore) SetAllowance(ctx context.Context, principalID uuid.UUID, granted *int, note string, setBy *uuid.UUID) error {
	if granted != nil && *granted < 0 {
		return fmt.Errorf("signupgate: an allowance cannot be negative, got %d", *granted)
	}
	err := s.client.SignupAllowance.Create().
		SetPrincipalID(principalID).
		SetNillableGranted(granted).
		SetNote(note).
		SetNillableSetByPrincipalID(setBy).
		OnConflictColumns(signupallowance.FieldPrincipalID).
		Update(func(u *ent.SignupAllowanceUpsert) {
			if granted != nil {
				u.SetGranted(*granted)
			} else {
				u.ClearGranted()
			}
			u.SetNote(note)
			if setBy != nil {
				u.SetSetByPrincipalID(*setBy)
			} else {
				u.ClearSetByPrincipalID()
			}
			u.SetUpdatedAt(s.now())
		}).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("signupgate: setting allowance: %w", err)
	}
	return nil
}

// PrincipalByEmail returns the principal ID of the account with the email
// address, or ErrNoAccount.
func (s *CodeStore) PrincipalByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return uuid.Nil, err
	}
	h, err := s.client.Human.Query().Where(human.EmailEQ(email)).Only(ctx)
	if ent.IsNotFound(err) {
		return uuid.Nil, fmt.Errorf("%w: %s", ErrNoAccount, email)
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("signupgate: reading account: %w", err)
	}
	return h.PrincipalID, nil
}

// Allowances returns the allowances operators have set, with each member's
// email and held count, ordered by email.
func (s *CodeStore) Allowances(ctx context.Context) ([]Allowance, error) {
	rows, err := s.client.SignupAllowance.Query().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("signupgate: listing allowances: %w", err)
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.PrincipalID)
	}
	humans, err := s.client.Human.Query().Where(human.PrincipalIDIn(ids...)).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("signupgate: reading accounts: %w", err)
	}
	emails := make(map[uuid.UUID]string, len(humans))
	for _, h := range humans {
		if h.Email != nil {
			emails[h.PrincipalID] = *h.Email
		}
	}
	now := s.now()
	out := make([]Allowance, 0, len(rows))
	for _, r := range rows {
		n, err := s.client.SignupCode.Query().Where(held(r.PrincipalID, now)).Count(ctx)
		if err != nil {
			return nil, fmt.Errorf("signupgate: counting member codes: %w", err)
		}
		out = append(out, Allowance{
			PrincipalID: r.PrincipalID, Email: emails[r.PrincipalID], Granted: r.Granted,
			Effective: s.effective(r.Granted), Held: n, Note: r.Note, SetBy: r.SetByPrincipalID,
			UpdatedAt: r.UpdatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

// MemberInvites returns a member's allowance, how many codes they hold, and
// their codes.
func (s *CodeStore) MemberInvites(ctx context.Context, principalID uuid.UUID) (MemberSummary, error) {
	var granted *int
	row, err := s.client.SignupAllowance.Query().Where(signupallowance.PrincipalIDEQ(principalID)).Only(ctx)
	switch {
	case err == nil:
		granted = row.Granted
	case !ent.IsNotFound(err):
		return MemberSummary{}, fmt.Errorf("signupgate: reading allowance: %w", err)
	}
	n, err := s.client.SignupCode.Query().Where(held(principalID, s.now())).Count(ctx)
	if err != nil {
		return MemberSummary{}, fmt.Errorf("signupgate: counting member codes: %w", err)
	}
	codes, err := s.ListCodes(ctx, CodeFilter{Kind: CodeMember, CreatedBy: &principalID})
	if err != nil {
		return MemberSummary{}, err
	}
	allowance := s.effective(granted)
	return MemberSummary{
		Allowance: allowance, Held: n, Remaining: max(allowance-n, 0), Codes: codes, CodeTTL: s.member.CodeTTL,
	}, nil
}

// CreateMemberCode creates a single-use code for a member, expiring after
// the member code TTL, and returns it with the code itself, shown once. It
// returns ErrAllowanceExhausted when the member holds their allowance
// already. The member's allowance row is written first inside the
// transaction, which locks it, so concurrent requests cannot both pass.
func (s *CodeStore) CreateMemberCode(ctx context.Context, principalID uuid.UUID) (Code, string, error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return Code{}, "", fmt.Errorf("signupgate: starting transaction: %w", err)
	}
	c, value, err := s.createMemberCode(ctx, tx, principalID)
	if err != nil {
		return Code{}, "", errors.Join(err, tx.Rollback())
	}
	if err := tx.Commit(); err != nil {
		return Code{}, "", fmt.Errorf("signupgate: creating member code: %w", err)
	}
	return c, value, nil
}

func (s *CodeStore) createMemberCode(ctx context.Context, tx *ent.Tx, principalID uuid.UUID) (Code, string, error) {
	now := s.now()
	err := tx.SignupAllowance.Create().
		SetPrincipalID(principalID).
		OnConflictColumns(signupallowance.FieldPrincipalID).
		Update(func(u *ent.SignupAllowanceUpsert) { u.SetUpdatedAt(now) }).
		Exec(ctx)
	if err != nil {
		return Code{}, "", fmt.Errorf("signupgate: locking allowance: %w", err)
	}
	row, err := tx.SignupAllowance.Query().Where(signupallowance.PrincipalIDEQ(principalID)).Only(ctx)
	if err != nil {
		return Code{}, "", fmt.Errorf("signupgate: reading allowance: %w", err)
	}
	n, err := tx.SignupCode.Query().Where(held(principalID, now)).Count(ctx)
	if err != nil {
		return Code{}, "", fmt.Errorf("signupgate: counting member codes: %w", err)
	}
	if n >= s.effective(row.Granted) {
		return Code{}, "", ErrAllowanceExhausted
	}
	expires := now.Add(s.member.CodeTTL)
	return s.createCode(ctx, tx.Client(), CodeOptions{
		Kind: CodeMember, MaxUses: 1, CreatedByPrincipal: &principalID, ExpiresAt: &expires,
	})
}

// RevokeMemberCode revokes one of a member's own codes. A code that was
// never used gives its slot back. It returns ErrCodeNotFound for a code
// the member did not create.
func (s *CodeStore) RevokeMemberCode(ctx context.Context, principalID, id uuid.UUID) error {
	return s.revoke(ctx,
		signupcode.IDEQ(id),
		signupcode.KindEQ(signupcode.KindMember),
		signupcode.CreatedByPrincipalIDEQ(principalID),
	)
}
