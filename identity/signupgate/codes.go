package signupgate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	"github.com/plexusone/systemforge/identity/ent/signupcode"
	"github.com/plexusone/systemforge/identity/ent/signupcoderedemption"
	"github.com/plexusone/systemforge/identity/systemauth"
)

var _ systemauth.SignupCodeLookup = (*CodeStore)(nil)

var (
	// ErrCodeInvalid means a code cannot be used: it is malformed, unknown,
	// used up, expired or revoked. The reason is not given, so a holder
	// cannot learn which codes exist.
	ErrCodeInvalid = errors.New("signupgate: invite code is not valid")

	// ErrCodeNotFound means no code has the given ID.
	ErrCodeNotFound = errors.New("signupgate: no such invite code")
)

// codeAlphabet is Crockford's base32 alphabet: digits and upper-case letters
// without I, L, O and U, so a code read aloud or retyped is unambiguous.
const codeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// codeLength is the number of characters in a code: 16 characters of 5 bits
// each, 80 bits in all.
const codeLength = 16

// CodeKind says who created a code.
type CodeKind string

const (
	// CodeOperator is a code an operator created; it may admit many people.
	CodeOperator CodeKind = "operator"
	// CodeMember is a code a member created from their allowance; it admits
	// one person.
	CodeMember CodeKind = "member"
)

// Code statuses, as returned by Code.Status.
const (
	CodeActive  = "active"
	CodeUsedUp  = "used_up"
	CodeExpired = "expired"
	CodeRevoked = "revoked"
)

// Code is an invite code as listed to operators and members. It never
// carries the code itself, which is shown only once, when created.
type Code struct {
	ID                 uuid.UUID
	Kind               CodeKind
	Hint               string // last four characters
	Label              string
	Note               string
	CreatedByPrincipal *uuid.UUID
	CreatedByLabel     string
	MaxUses            int
	UseCount           int
	CreatedAt          time.Time
	ExpiresAt          *time.Time
	RevokedAt          *time.Time
}

// Status is CodeRevoked, CodeExpired, CodeUsedUp or CodeActive at the given
// time, in that order of precedence.
func (c Code) Status(now time.Time) string {
	switch {
	case c.RevokedAt != nil:
		return CodeRevoked
	case c.ExpiresAt != nil && !c.ExpiresAt.After(now):
		return CodeExpired
	case c.UseCount >= c.MaxUses:
		return CodeUsedUp
	default:
		return CodeActive
	}
}

// CodeOptions describe a new code.
type CodeOptions struct {
	// Kind is CodeOperator or CodeMember.
	Kind CodeKind
	// Label names the cohort, such as "launch-week".
	Label string
	// Note is free-text context for operators.
	Note string
	// CreatedByPrincipal is the person creating the code through the API.
	CreatedByPrincipal *uuid.UUID
	// CreatedByLabel labels an operator creating the code from the command
	// line.
	CreatedByLabel string
	// MaxUses is how many accounts the code may create; at least 1.
	MaxUses int
	// ExpiresAt ends the code; nil means it does not expire.
	ExpiresAt *time.Time
}

// CodeFilter narrows ListCodes. The zero value lists every code.
type CodeFilter struct {
	// Kind keeps codes of one kind.
	Kind CodeKind
	// Label keeps codes with this label.
	Label string
	// CreatedBy keeps codes created by this principal.
	CreatedBy *uuid.UUID
	// ActiveOnly keeps codes that can still be used.
	ActiveOnly bool
}

// Redemption is an account created with a code.
type Redemption struct {
	ID          uuid.UUID
	CodeID      uuid.UUID
	PrincipalID uuid.UUID
	Email       string
	CreatedAt   time.Time
	// The code's kind, label, hint and creator, for attribution.
	CodeKind           CodeKind
	CodeLabel          string
	CodeHint           string
	CodeCreatedBy      *uuid.UUID
	CodeCreatedByLabel string
}

// RedemptionFilter narrows Redemptions. The zero value lists every
// redemption.
type RedemptionFilter struct {
	// CodeID keeps accounts created with this code.
	CodeID *uuid.UUID
	// CreatedBy keeps accounts created with codes this principal created.
	CreatedBy *uuid.UUID
	// Label keeps accounts created with codes carrying this label.
	Label string
}

// CodeStore reads and writes invite codes, their redemptions and member
// allowances.
type CodeStore struct {
	client *ent.Client
	member MemberOptions
	now    func() time.Time
}

// NewCodeStore returns a CodeStore over client. Member invites use the
// given options, with defaults for zero fields.
func NewCodeStore(client *ent.Client, member MemberOptions) *CodeStore {
	return &CodeStore{client: client, member: member.withDefaults(), now: time.Now}
}

// NormalizeCode returns the stored form of a code: upper-case, without
// dashes or spaces, with O read as 0 and I and L read as 1. It returns
// ErrCodeInvalid for anything that is not a code.
func NormalizeCode(raw string) (string, error) {
	var b strings.Builder
	for _, r := range strings.ToUpper(raw) {
		switch r {
		case '-', ' ':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(codeAlphabet, r) {
			return "", ErrCodeInvalid
		}
		b.WriteRune(r)
	}
	if b.Len() != codeLength {
		return "", ErrCodeInvalid
	}
	return b.String(), nil
}

// FormatCode returns a normalized code in groups of four, as shown to people:
// XXXX-XXXX-XXXX-XXXX.
func FormatCode(normalized string) string {
	var b strings.Builder
	for i, r := range normalized {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// generateCode returns a new random normalized code.
func generateCode() (string, error) {
	buf := make([]byte, codeLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("signupgate: generating invite code: %w", err)
	}
	out := make([]byte, codeLength)
	for i, v := range buf {
		out[i] = codeAlphabet[v&31] // 256 is a multiple of 32, so this is uniform
	}
	return string(out), nil
}

func hashCode(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

// CreateCode creates a code and returns it with the code itself, formatted
// for people. The code is not stored and cannot be shown again.
func (s *CodeStore) CreateCode(ctx context.Context, opts CodeOptions) (Code, string, error) {
	return s.createCode(ctx, s.client, opts)
}

func (s *CodeStore) createCode(ctx context.Context, client *ent.Client, opts CodeOptions) (Code, string, error) {
	if opts.Kind != CodeOperator && opts.Kind != CodeMember {
		return Code{}, "", fmt.Errorf("signupgate: unknown code kind %q", opts.Kind)
	}
	if opts.MaxUses < 1 {
		return Code{}, "", fmt.Errorf("signupgate: an invite code needs at least one use, got %d", opts.MaxUses)
	}
	code, err := generateCode()
	if err != nil {
		return Code{}, "", err
	}
	c := client.SignupCode.Create().
		SetCodeHash(hashCode(code)).
		SetCodeHint(code[codeLength-4:]).
		SetKind(signupcode.Kind(opts.Kind)).
		SetLabel(opts.Label).
		SetNote(opts.Note).
		SetCreatedByLabel(opts.CreatedByLabel).
		SetMaxUses(opts.MaxUses).
		SetNillableCreatedByPrincipalID(opts.CreatedByPrincipal).
		SetNillableExpiresAt(opts.ExpiresAt).
		SetCreatedAt(s.now())
	saved, err := c.Save(ctx)
	if err != nil {
		return Code{}, "", fmt.Errorf("signupgate: creating invite code: %w", err)
	}
	return toCode(saved), FormatCode(code), nil
}

// ListCodes returns codes, newest first.
func (s *CodeStore) ListCodes(ctx context.Context, f CodeFilter) ([]Code, error) {
	q := s.client.SignupCode.Query()
	if f.Kind != "" {
		q = q.Where(signupcode.KindEQ(signupcode.Kind(f.Kind)))
	}
	if f.Label != "" {
		q = q.Where(signupcode.LabelEQ(f.Label))
	}
	if f.CreatedBy != nil {
		q = q.Where(signupcode.CreatedByPrincipalIDEQ(*f.CreatedBy))
	}
	if f.ActiveOnly {
		q = q.Where(usable(s.now()))
	}
	rows, err := q.Order(ent.Desc(signupcode.FieldCreatedAt), ent.Desc(signupcode.FieldID)).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("signupgate: listing invite codes: %w", err)
	}
	out := make([]Code, 0, len(rows))
	for _, r := range rows {
		out = append(out, toCode(r))
	}
	return out, nil
}

// GetCode returns the code with the given ID, or ErrCodeNotFound.
func (s *CodeStore) GetCode(ctx context.Context, id uuid.UUID) (Code, error) {
	r, err := s.client.SignupCode.Get(ctx, id)
	if ent.IsNotFound(err) {
		return Code{}, fmt.Errorf("%w: %s", ErrCodeNotFound, id)
	}
	if err != nil {
		return Code{}, fmt.Errorf("signupgate: reading invite code: %w", err)
	}
	return toCode(r), nil
}

// RevokeCode revokes a code, so it admits nobody else. Accounts already
// created with it are not touched. Revoking a revoked code changes nothing.
// It returns ErrCodeNotFound when there is no such code.
func (s *CodeStore) RevokeCode(ctx context.Context, id uuid.UUID) error {
	return s.revoke(ctx, signupcode.IDEQ(id))
}

func (s *CodeStore) revoke(ctx context.Context, where ...predicate.SignupCode) error {
	n, err := s.client.SignupCode.Update().
		Where(append(where, signupcode.RevokedAtIsNil())...).
		SetRevokedAt(s.now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("signupgate: revoking invite code: %w", err)
	}
	if n > 0 {
		return nil
	}
	exists, err := s.client.SignupCode.Query().Where(where...).Exist(ctx)
	if err != nil {
		return fmt.Errorf("signupgate: reading invite code: %w", err)
	}
	if !exists {
		return ErrCodeNotFound
	}
	return nil
}

// Lookup returns the code a person holds, whatever its status, or
// ErrCodeInvalid when it is malformed or unknown.
func (s *CodeStore) Lookup(ctx context.Context, code string) (Code, error) {
	normalized, err := NormalizeCode(code)
	if err != nil {
		return Code{}, err
	}
	r, err := s.client.SignupCode.Query().Where(signupcode.CodeHashEQ(hashCode(normalized))).Only(ctx)
	if ent.IsNotFound(err) {
		return Code{}, ErrCodeInvalid
	}
	if err != nil {
		return Code{}, fmt.Errorf("signupgate: reading invite code: %w", err)
	}
	return toCode(r), nil
}

// Reserve takes one use of a code and returns the code's ID. It is one
// conditional update, so a code with N uses is reserved at most N times
// however many sign-ups race for it. It returns ErrCodeInvalid when the code
// cannot be used, for any reason.
func (s *CodeStore) Reserve(ctx context.Context, code string) (uuid.UUID, error) {
	normalized, err := NormalizeCode(code)
	if err != nil {
		return uuid.Nil, err
	}
	hash := hashCode(normalized)
	n, err := s.client.SignupCode.Update().
		Where(signupcode.CodeHashEQ(hash), usable(s.now())).
		AddUseCount(1).
		Save(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("signupgate: reserving invite code: %w", err)
	}
	if n == 0 {
		return uuid.Nil, ErrCodeInvalid
	}
	id, err := s.client.SignupCode.Query().Where(signupcode.CodeHashEQ(hash)).OnlyID(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("signupgate: reading reserved invite code: %w", err)
	}
	return id, nil
}

// Release gives back a use taken by Reserve, when the account it was
// reserved for was not created.
func (s *CodeStore) Release(ctx context.Context, id uuid.UUID) error {
	_, err := s.client.SignupCode.Update().
		Where(signupcode.IDEQ(id), signupcode.UseCountGT(0)).
		AddUseCount(-1).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("signupgate: releasing invite code: %w", err)
	}
	return nil
}

// Redeem records that the account was created with a code reserved by
// Reserve.
func (s *CodeStore) Redeem(ctx context.Context, id, principalID uuid.UUID, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	_, err := s.client.SignupCodeRedemption.Create().
		SetCodeID(id).
		SetPrincipalID(principalID).
		SetEmail(email).
		SetCreatedAt(s.now()).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("signupgate: recording invite code redemption: %w", err)
	}
	return nil
}

// Redemptions returns accounts created with codes, newest first.
func (s *CodeStore) Redemptions(ctx context.Context, f RedemptionFilter) ([]Redemption, error) {
	q := s.client.SignupCodeRedemption.Query().WithCode()
	if f.CodeID != nil {
		q = q.Where(signupcoderedemption.CodeIDEQ(*f.CodeID))
	}
	if f.CreatedBy != nil {
		q = q.Where(signupcoderedemption.HasCodeWith(signupcode.CreatedByPrincipalIDEQ(*f.CreatedBy)))
	}
	if f.Label != "" {
		q = q.Where(signupcoderedemption.HasCodeWith(signupcode.LabelEQ(f.Label)))
	}
	rows, err := q.Order(ent.Desc(signupcoderedemption.FieldCreatedAt), ent.Desc(signupcoderedemption.FieldID)).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("signupgate: listing invite code redemptions: %w", err)
	}
	out := make([]Redemption, 0, len(rows))
	for _, r := range rows {
		red := Redemption{
			ID: r.ID, CodeID: r.CodeID, PrincipalID: r.PrincipalID, Email: r.Email, CreatedAt: r.CreatedAt,
		}
		if c := r.Edges.Code; c != nil {
			red.CodeKind = CodeKind(c.Kind)
			red.CodeLabel = c.Label
			red.CodeHint = c.CodeHint
			red.CodeCreatedBy = c.CreatedByPrincipalID
			red.CodeCreatedByLabel = c.CreatedByLabel
		}
		out = append(out, red)
	}
	return out, nil
}

// usable matches codes that can still be used at now: not revoked, not
// expired, and with uses left.
func usable(now time.Time) predicate.SignupCode {
	return signupcode.And(
		signupcode.RevokedAtIsNil(),
		signupcode.Or(signupcode.ExpiresAtIsNil(), signupcode.ExpiresAtGT(now)),
		predicate.SignupCode(func(s *sql.Selector) {
			s.Where(sql.ColumnsLT(s.C(signupcode.FieldUseCount), s.C(signupcode.FieldMaxUses)))
		}),
	)
}

func toCode(r *ent.SignupCode) Code {
	return Code{
		ID: r.ID, Kind: CodeKind(r.Kind), Hint: r.CodeHint, Label: r.Label, Note: r.Note,
		CreatedByPrincipal: r.CreatedByPrincipalID, CreatedByLabel: r.CreatedByLabel,
		MaxUses: r.MaxUses, UseCount: r.UseCount, CreatedAt: r.CreatedAt,
		ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt,
	}
}

// CodeLink returns the invite link for a code: the sign-up page URL with the
// code as its code query parameter.
func CodeLink(signupURL, code string) string {
	u, err := url.Parse(signupURL)
	if err != nil {
		return signupURL + "?code=" + url.QueryEscape(code)
	}
	q := u.Query()
	q.Set("code", code)
	u.RawQuery = q.Encode()
	return u.String()
}

// SignupCodeUsable implements systemauth.SignupCodeLookup: it returns the
// code in its stored form and whether it can be used now.
func (s *CodeStore) SignupCodeUsable(ctx context.Context, code string) (string, bool, error) {
	normalized, err := NormalizeCode(code)
	if err != nil {
		return "", false, nil //nolint:nilerr // a malformed code is not usable; it is refused, not a fault
	}
	c, err := s.Lookup(ctx, normalized)
	if errors.Is(err, ErrCodeInvalid) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return normalized, c.Status(s.now()) == CodeActive, nil
}
