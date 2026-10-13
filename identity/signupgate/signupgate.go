// Package signupgate keeps platform sign-up invites and implements the
// systemauth.SignupGate that enforces them. With the gate installed a
// deployment creates accounts only for verified emails that hold an invite;
// people who already have an account sign in as before.
//
// An invite is an email address, not a code: the person proves control of
// the address by signing in through the upstream provider, and the gate
// compares that verified address with the invites. Nothing is sent and
// nothing needs to be typed.
package signupgate

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/signupinvite"
	"github.com/plexusone/systemforge/identity/systemauth"
)

var (
	// ErrInvalidEmail means the address is not a plain email address.
	ErrInvalidEmail = errors.New("signupgate: not a plain email address")

	// ErrAlreadyRedeemed means an account was already created with the
	// invite. Revoke it to invite the address again.
	ErrAlreadyRedeemed = errors.New("signupgate: invite already redeemed")

	// ErrNotFound means no invite exists for the address.
	ErrNotFound = errors.New("signupgate: no invite for that address")
)

// Invite is a sign-up invite as listed to operators.
type Invite struct {
	Email      string
	Note       string
	InvitedBy  string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RedeemedAt *time.Time
	RedeemedBy *uuid.UUID
}

// Status is "redeemed", "expired" or "pending" at the given time.
func (i Invite) Status(now time.Time) string {
	switch {
	case i.RedeemedAt != nil:
		return "redeemed"
	case i.ExpiresAt != nil && !i.ExpiresAt.After(now):
		return "expired"
	default:
		return "pending"
	}
}

// AddOptions are the optional parts of a new invite.
type AddOptions struct {
	// Note is free-text context for operators.
	Note string
	// InvitedBy labels the operator creating the invite.
	InvitedBy string
	// ExpiresAt ends the invite; nil means it does not expire.
	ExpiresAt *time.Time
}

// Store reads and writes invites.
type Store struct {
	client *ent.Client
	now    func() time.Time
}

// NewStore returns a Store over client.
func NewStore(client *ent.Client) *Store {
	return &Store{client: client, now: time.Now}
}

// NormalizeEmail returns the stored form of an address: trimmed and
// lower-case. A display name, a comment or a missing domain is refused.
func NormalizeEmail(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	addr, err := mail.ParseAddress(raw)
	if err != nil || addr.Name != "" || addr.Address != raw {
		return "", fmt.Errorf("%w: %q", ErrInvalidEmail, raw)
	}
	at := strings.LastIndex(addr.Address, "@")
	if at <= 0 || !strings.Contains(addr.Address[at+1:], ".") {
		return "", fmt.Errorf("%w: %q", ErrInvalidEmail, raw)
	}
	return strings.ToLower(addr.Address), nil
}

// Add creates an invite, or updates the note, label and expiry of a pending
// one. It returns ErrAlreadyRedeemed for an address that already has an
// account created through its invite.
func (s *Store) Add(ctx context.Context, email string, opts AddOptions) (*Invite, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return nil, err
	}
	existing, err := s.client.SignupInvite.Query().Where(signupinvite.EmailEQ(email)).Only(ctx)
	switch {
	case err == nil:
		if existing.RedeemedAt != nil {
			return nil, fmt.Errorf("%w: %s", ErrAlreadyRedeemed, email)
		}
		u := existing.Update().SetNote(opts.Note).SetInvitedBy(opts.InvitedBy)
		if opts.ExpiresAt != nil {
			u.SetExpiresAt(*opts.ExpiresAt)
		} else {
			u.ClearExpiresAt()
		}
		saved, err := u.Save(ctx)
		if err != nil {
			return nil, fmt.Errorf("signupgate: updating invite: %w", err)
		}
		return toInvite(saved), nil
	case !ent.IsNotFound(err):
		return nil, fmt.Errorf("signupgate: reading invite: %w", err)
	}
	c := s.client.SignupInvite.Create().SetEmail(email).SetNote(opts.Note).SetInvitedBy(opts.InvitedBy)
	if opts.ExpiresAt != nil {
		c.SetExpiresAt(*opts.ExpiresAt)
	}
	saved, err := c.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("signupgate: creating invite: %w", err)
	}
	return toInvite(saved), nil
}

// Revoke deletes the invite for an address, redeemed or not. Deleting a
// redeemed invite does not touch the account created with it; it only lets
// the address be invited again. It returns ErrNotFound when there is none.
func (s *Store) Revoke(ctx context.Context, email string) error {
	email, err := NormalizeEmail(email)
	if err != nil {
		return err
	}
	n, err := s.client.SignupInvite.Delete().Where(signupinvite.EmailEQ(email)).Exec(ctx)
	if err != nil {
		return fmt.Errorf("signupgate: revoking invite: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, email)
	}
	return nil
}

// List returns invites ordered by address. Redeemed invites are included
// only when includeRedeemed is set.
func (s *Store) List(ctx context.Context, includeRedeemed bool) ([]Invite, error) {
	q := s.client.SignupInvite.Query()
	if !includeRedeemed {
		q = q.Where(signupinvite.RedeemedAtIsNil())
	}
	rows, err := q.All(ctx)
	if err != nil {
		return nil, fmt.Errorf("signupgate: listing invites: %w", err)
	}
	out := make([]Invite, 0, len(rows))
	for _, r := range rows {
		out = append(out, *toInvite(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

// Allowed reports whether the address holds an invite that is neither
// redeemed nor expired.
func (s *Store) Allowed(ctx context.Context, email string) (bool, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return false, nil //nolint:nilerr // an address that is not an email holds no invite; it is refused, not a fault
	}
	inv, err := s.client.SignupInvite.Query().Where(signupinvite.EmailEQ(email)).Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("signupgate: reading invite: %w", err)
	}
	return toInvite(inv).Status(s.now()) == "pending", nil
}

// Redeem marks the invite for an address as used by the principal. It does
// nothing, and reports no error, when the invite was already used, so a
// repeated call is harmless.
func (s *Store) Redeem(ctx context.Context, email string, principalID uuid.UUID) error {
	email, err := NormalizeEmail(email)
	if err != nil {
		return err
	}
	_, err = s.client.SignupInvite.Update().
		Where(signupinvite.EmailEQ(email), signupinvite.RedeemedAtIsNil()).
		SetRedeemedAt(s.now()).
		SetRedeemedBy(principalID).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("signupgate: redeeming invite: %w", err)
	}
	return nil
}

func toInvite(r *ent.SignupInvite) *Invite {
	return &Invite{
		Email: r.Email, Note: r.Note, InvitedBy: r.InvitedBy, CreatedAt: r.CreatedAt,
		ExpiresAt: r.ExpiresAt, RedeemedAt: r.RedeemedAt, RedeemedBy: r.RedeemedBy,
	}
}

// Gate is the systemauth.SignupGate over a Store.
type Gate struct {
	store *Store
}

var _ systemauth.SignupGate = (*Gate)(nil)

// NewGate returns a gate that allows a sign-up when the login's verified
// email holds a pending invite.
func NewGate(store *Store) *Gate { return &Gate{store: store} }

// AllowSignup implements systemauth.SignupGate. Only a verified email can
// match: an unverified address is never trusted, and the directory refuses
// to create an account for one anyway.
func (g *Gate) AllowSignup(ctx context.Context, login systemauth.ExternalLogin) error {
	if !login.EmailVerified {
		return systemauth.ErrSignupNotInvited
	}
	ok, err := g.store.Allowed(ctx, login.Email)
	if err != nil {
		return err
	}
	if !ok {
		return systemauth.ErrSignupNotInvited
	}
	return nil
}

// SignedUp implements systemauth.SignupGate by consuming the invite.
func (g *Gate) SignedUp(ctx context.Context, login systemauth.ExternalLogin, principalID uuid.UUID) error {
	return g.store.Redeem(ctx, login.Email, principalID)
}
