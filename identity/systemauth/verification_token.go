package systemauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// VerificationPurpose scopes a verification token to one use (ADR-003). A
// token issued for one purpose is never accepted for another.
type VerificationPurpose string

// Verification token purposes.
const (
	// PurposeVerifyEmail verifies the unverified provider email of a
	// pending social sign-in.
	PurposeVerifyEmail VerificationPurpose = "verify_email"
	// PurposeEmailChange verifies the new address of a signed-in
	// principal's email change.
	PurposeEmailChange VerificationPurpose = "email_change"
	// PurposeSignInCode proves control of an address for an email
	// one-time code sign-in (ADR-023). It is the one purpose whose secret
	// is short enough to guess, so it is used through RecordAttempt.
	PurposeSignInCode VerificationPurpose = "sign_in_code"
	// PurposeSignUpName holds a sign-up whose account waits for the person's
	// name: the login is proven and parked, bound to the browser, until the
	// name form is answered.
	PurposeSignUpName VerificationPurpose = "sign_up_name"
)

// Valid reports whether p is a known purpose.
func (p VerificationPurpose) Valid() bool {
	return p == PurposeVerifyEmail || p == PurposeEmailChange || p == PurposeSignInCode || p == PurposeSignUpName
}

// DefaultVerificationTokenTTL is how long a verification link works when
// no other lifetime is configured.
const DefaultVerificationTokenTTL = 30 * time.Minute

var (
	// ErrVerificationTokenInvalid is returned by Consume for a token that
	// is unknown, expired, already used or revoked, issued for another
	// purpose, or presented without its binding. The cases are not
	// distinguished, so a caller cannot learn which applies.
	ErrVerificationTokenInvalid = errors.New("systemauth: verification token is invalid or expired")

	// ErrVerificationTokenNotFound is returned by Latest when the binding
	// has no usable token.
	ErrVerificationTokenNotFound = errors.New("systemauth: no pending verification")
)

// VerificationToken is a stored email verification token. The token value
// itself is never stored: stores keep a SHA-256 hash of it.
type VerificationToken struct {
	// ID identifies the stored row.
	ID uuid.UUID
	// Purpose is what the token may be used for.
	Purpose VerificationPurpose
	// Email is the address the token was mailed to and verifies.
	Email string
	// PrincipalID is the principal the token acts for (email change), or
	// uuid.Nil for a pending sign-in.
	PrincipalID uuid.UUID
	// Binding is what a confirmation must present, so a token is useless
	// to anyone who has only the link: a hash of the pending sign-in's
	// browser cookie, or the principal for an email change. It is an
	// opaque, non-secret string; a caller binding to a secret passes a
	// hash of it.
	Binding string
	// Data is a purpose-specific payload, such as the pending sign-in.
	Data []byte
	// CreatedAt is when the token was issued.
	CreatedAt time.Time
	// ExpiresAt is when the token stops being accepted.
	ExpiresAt time.Time
	// Attempts is how many attempts RecordAttempt has counted.
	Attempts int
	// ConsumedAt is when the token was used or revoked; nil while it is
	// usable.
	ConsumedAt *time.Time
}

// VerificationTokenStore persists verification tokens. Implementations
// store only a hash of the token, must be safe for concurrent use, and
// must make Consume single-use across every instance sharing the store.
// storetest.VerificationTokenStore is the conformance suite.
type VerificationTokenStore interface {
	// Create stores t under token. CreatedAt defaults to now and
	// ExpiresAt to CreatedAt plus DefaultVerificationTokenTTL.
	Create(ctx context.Context, token string, t VerificationToken) error

	// Consume marks the token used and returns it, provided it was issued
	// for purpose and binding, is unexpired and was not used or revoked.
	// The check and the mark are one atomic step: of concurrent calls for
	// the same token at most one succeeds. Otherwise it returns
	// ErrVerificationTokenInvalid and changes nothing, so a wrong binding
	// cannot burn someone else's token.
	Consume(ctx context.Context, token string, purpose VerificationPurpose, binding string) (*VerificationToken, error)

	// Latest returns the most recently issued usable token for purpose and
	// binding, or ErrVerificationTokenNotFound.
	Latest(ctx context.Context, purpose VerificationPurpose, binding string) (*VerificationToken, error)

	// RecordAttempt counts one attempt against the most recently issued
	// usable token for purpose and binding, and returns it with Attempts
	// including this attempt. The check and the count are one atomic step:
	// across concurrent calls and instances at most limit attempts are
	// counted, however many guesses arrive. Once a token has had limit
	// attempts it returns ErrVerificationTokenInvalid, as it does when
	// there is no usable token, and changes nothing. The caller compares
	// its secret with the returned token and, when it matches, uses
	// Consume; a wrong guess needs no further call.
	RecordAttempt(ctx context.Context, purpose VerificationPurpose, binding string, limit int) (*VerificationToken, error)

	// ConsumeToken marks the token with id used, provided it was issued for
	// purpose and binding, is unexpired, was not used or revoked, and no
	// newer token of the same purpose and binding exists: a token that a
	// newer one replaced is dead whether or not the newer one is still
	// usable. The checks and the mark are one atomic step, so of concurrent
	// calls at most one succeeds, a token being replaced while it is
	// consumed is decided one way or the other and never both, and the
	// replacement is never touched. Otherwise it returns
	// ErrVerificationTokenInvalid and changes nothing.
	ConsumeToken(ctx context.Context, id uuid.UUID, purpose VerificationPurpose, binding string) error

	// Revoke marks every usable token for purpose and binding consumed and
	// returns how many it revoked.
	Revoke(ctx context.Context, purpose VerificationPurpose, binding string) (int, error)

	// DeleteExpired removes expired tokens, used or not, and returns how
	// many it removed.
	DeleteExpired(ctx context.Context) (int, error)
}

// prepareVerificationToken validates t and fills its defaults.
func prepareVerificationToken(token string, t *VerificationToken, now time.Time) error {
	switch {
	case token == "":
		return errors.New("systemauth: empty verification token")
	case !t.Purpose.Valid():
		return fmt.Errorf("systemauth: unknown verification purpose %q", t.Purpose)
	case t.Email == "":
		return errors.New("systemauth: verification token needs an email")
	case t.Binding == "":
		return errors.New("systemauth: verification token needs a binding")
	}
	if t.ID == uuid.Nil {
		// A time-ordered ID: tokens issued at the same instant (a coarse
		// clock) still order by issue, which the "newest token" rules
		// (Latest, RecordAttempt, ConsumeToken) depend on.
		id, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("systemauth: generating a verification token ID: %w", err)
		}
		t.ID = id
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	if t.ExpiresAt.IsZero() {
		t.ExpiresAt = t.CreatedAt.Add(DefaultVerificationTokenTTL)
	}
	t.ConsumedAt = nil
	return nil
}

// newerThan reports whether t was issued after o: later, or at the same
// time with a greater ID, the order Latest uses.
func (t *VerificationToken) newerThan(o *VerificationToken) bool {
	if !t.CreatedAt.Equal(o.CreatedAt) {
		return t.CreatedAt.After(o.CreatedAt)
	}
	return bytes.Compare(t.ID[:], o.ID[:]) > 0
}

// usable reports whether t can still be consumed at now.
func (t *VerificationToken) usable(now time.Time) bool {
	return t.ConsumedAt == nil && now.Before(t.ExpiresAt)
}

func (t *VerificationToken) clone() *VerificationToken {
	cp := *t
	cp.Data = slices.Clone(t.Data)
	if t.ConsumedAt != nil {
		at := *t.ConsumedAt
		cp.ConsumedAt = &at
	}
	return &cp
}

// MemoryVerificationTokenStore is an in-memory VerificationTokenStore for
// a single instance and tests.
type MemoryVerificationTokenStore struct {
	mu     sync.Mutex
	tokens map[string]*VerificationToken
	now    func() time.Time
}

// NewMemoryVerificationTokenStore creates an empty in-memory store.
func NewMemoryVerificationTokenStore() *MemoryVerificationTokenStore {
	return &MemoryVerificationTokenStore{tokens: map[string]*VerificationToken{}, now: time.Now}
}

// Create implements VerificationTokenStore.
func (s *MemoryVerificationTokenStore) Create(_ context.Context, token string, t VerificationToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if err := prepareVerificationToken(token, &t, now); err != nil {
		return err
	}
	key := hashSessionToken(token)
	if _, ok := s.tokens[key]; ok {
		return errors.New("systemauth: verification token already exists")
	}
	s.deleteExpiredLocked(now)
	s.tokens[key] = t.clone()
	return nil
}

// Consume implements VerificationTokenStore.
func (s *MemoryVerificationTokenStore) Consume(_ context.Context, token string, purpose VerificationPurpose, binding string) (*VerificationToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	t, ok := s.tokens[hashSessionToken(token)]
	if !ok || t.Purpose != purpose || t.Binding != binding || binding == "" || !t.usable(now) {
		return nil, ErrVerificationTokenInvalid
	}
	t.ConsumedAt = &now
	return t.clone(), nil
}

// Latest implements VerificationTokenStore.
func (s *MemoryVerificationTokenStore) Latest(_ context.Context, purpose VerificationPurpose, binding string) (*VerificationToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var found []*VerificationToken
	for _, t := range s.tokens {
		if t.Purpose == purpose && t.Binding == binding && t.usable(now) {
			found = append(found, t)
		}
	}
	if len(found) == 0 {
		return nil, ErrVerificationTokenNotFound
	}
	sort.Slice(found, func(i, j int) bool { return found[i].newerThan(found[j]) })
	return found[0].clone(), nil
}

// ConsumeToken implements VerificationTokenStore.
func (s *MemoryVerificationTokenStore) ConsumeToken(_ context.Context, id uuid.UUID, purpose VerificationPurpose, binding string) error {
	if binding == "" {
		return ErrVerificationTokenInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var row *VerificationToken
	for _, t := range s.tokens {
		if t.ID == id {
			row = t
			break
		}
	}
	if row == nil || row.Purpose != purpose || row.Binding != binding || !row.usable(now) {
		return ErrVerificationTokenInvalid
	}
	for _, t := range s.tokens {
		if t != row && t.Purpose == purpose && t.Binding == binding && t.newerThan(row) {
			return ErrVerificationTokenInvalid
		}
	}
	row.ConsumedAt = &now
	return nil
}

// RecordAttempt implements VerificationTokenStore.
func (s *MemoryVerificationTokenStore) RecordAttempt(_ context.Context, purpose VerificationPurpose, binding string, limit int) (*VerificationToken, error) {
	if limit < 1 || !purpose.Valid() || binding == "" {
		return nil, ErrVerificationTokenInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var latest *VerificationToken
	for _, t := range s.tokens {
		if t.Purpose == purpose && t.Binding == binding && t.usable(now) &&
			(latest == nil || t.newerThan(latest)) {
			latest = t
		}
	}
	if latest == nil || latest.Attempts >= limit {
		return nil, ErrVerificationTokenInvalid
	}
	latest.Attempts++
	return latest.clone(), nil
}

// Revoke implements VerificationTokenStore.
func (s *MemoryVerificationTokenStore) Revoke(_ context.Context, purpose VerificationPurpose, binding string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for _, t := range s.tokens {
		if t.Purpose == purpose && t.Binding == binding && t.usable(now) {
			t.ConsumedAt = &now
			n++
		}
	}
	return n, nil
}

// DeleteExpired implements VerificationTokenStore.
func (s *MemoryVerificationTokenStore) DeleteExpired(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteExpiredLocked(s.now()), nil
}

func (s *MemoryVerificationTokenStore) deleteExpiredLocked(now time.Time) int {
	n := 0
	for k, t := range s.tokens {
		if !now.Before(t.ExpiresAt) {
			delete(s.tokens, k)
			n++
		}
	}
	return n
}

var _ VerificationTokenStore = (*MemoryVerificationTokenStore)(nil)
