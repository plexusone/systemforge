package managedprincipal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/managerclaim"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/principal"
)

const (
	// ClaimCodePrefix starts every claim code. Codes use only uppercase
	// letters and digits, for QR codes and printed letters.
	ClaimCodePrefix = "SFMC"
	// claimCodeBytes is the randomness in a claim code: 160 bits, short
	// enough to type from paper.
	claimCodeBytes = 20
	// claimPrefixLen is the stored, displayable lookup prefix.
	claimPrefixLen = len(ClaimCodePrefix) + 8

	// DefaultClaimTTL is how long a claim code stays redeemable: long
	// enough for a letter sent home to reach a parent.
	DefaultClaimTTL = 7 * 24 * time.Hour

	// Audit event types for claims and attaching an email.
	EventClaimIssued   = "managed_principal.claim_issued"
	EventClaimRedeemed = "managed_principal.claim_redeemed"
	EventEmailAttached = "managed_principal.email_attached"
)

var (
	// ErrInvalidClaim is returned for every claim code that cannot be
	// redeemed: unknown, malformed, expired, or already redeemed.
	ErrInvalidClaim = errors.New("managedprincipal: invalid claim code")
	// ErrEmailInUse is returned when attaching an email another human
	// already has.
	ErrEmailInUse = errors.New("managedprincipal: email is already in use")
	// ErrEmailRequired is returned when attaching an empty email.
	ErrEmailRequired = errors.New("managedprincipal: email is required")
)

var claimEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// WithClaimTTL sets how long claim codes stay redeemable. Defaults to
// DefaultClaimTTL.
func WithClaimTTL(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 {
			s.claimTTL = d
		}
	}
}

// Claim is a newly issued claim code. Code is available only here.
type Claim struct {
	ID        uuid.UUID
	Code      string
	ExpiresAt time.Time
}

// IssueClaim issues a single-use code with which a human with an email
// becomes guardian of a managed principal, for example a parent receiving
// a letter from a teacher. The issuer needs manage_credentials, which
// guardians and educators hold.
func (s *Service) IssueClaim(ctx context.Context, actorID, managedID uuid.UUID) (*Claim, error) {
	if err := s.authorizeCredentials(ctx, actorID, managedID); err != nil {
		return nil, err
	}
	randomBytes := make([]byte, claimCodeBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("managedprincipal: generate claim code: %w", err)
	}
	code := ClaimCodePrefix + claimEncoding.EncodeToString(randomBytes)
	expiresAt := s.now().Add(s.claimTTL)
	row, err := s.client.ManagerClaim.Create().
		SetManagedPrincipalID(managedID).
		SetCodePrefix(code[:claimPrefixLen]).
		SetCodeHash(hashCode(code)).
		SetIssuedBy(actorID).
		SetExpiresAt(expiresAt).
		SetCreatedAt(s.now()).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: store claim: %w", err)
	}
	s.emit(ctx, EventClaimIssued, "issue_claim", actorID, managedID,
		map[string]any{"claim_id": row.ID.String(), "expires_at": expiresAt})
	return &Claim{ID: row.ID, Code: code, ExpiresAt: expiresAt}, nil
}

// RedeemClaim makes claimantID a guardian of the claim's managed principal
// and spends the claim. The claimant must be an active human with an
// email who is not managed. It returns the managed principal's ID.
func (s *Service) RedeemClaim(ctx context.Context, code string, claimantID uuid.UUID) (uuid.UUID, error) {
	code = normalizeCode(code)
	if len(code) <= claimPrefixLen || !strings.HasPrefix(code, ClaimCodePrefix) {
		return uuid.Nil, ErrInvalidClaim
	}
	var managedID uuid.UUID
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		c, err := tx.ManagerClaim.Query().Where(managerclaim.CodePrefix(code[:claimPrefixLen])).Only(ctx)
		if ent.IsNotFound(err) {
			return ErrInvalidClaim
		}
		if err != nil {
			return fmt.Errorf("managedprincipal: find claim: %w", err)
		}
		want, err := hex.DecodeString(c.CodeHash)
		if err != nil {
			return fmt.Errorf("managedprincipal: corrupt claim hash %s: %w", c.ID, err)
		}
		got := sha256.Sum256([]byte(code))
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return ErrInvalidClaim
		}
		now := s.now()
		if c.RedeemedAt != nil || !c.ExpiresAt.After(now) {
			return ErrInvalidClaim
		}
		// Spend the claim conditionally so concurrent redemptions cannot
		// both succeed.
		n, err := tx.ManagerClaim.Update().
			Where(managerclaim.ID(c.ID), managerclaim.RedeemedAtIsNil()).
			SetRedeemedAt(now).
			SetRedeemedBy(claimantID).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("managedprincipal: spend claim: %w", err)
		}
		if n != 1 {
			return ErrInvalidClaim
		}
		if _, err := lockHuman(ctx, tx, c.ManagedPrincipalID); err != nil {
			return err
		}
		if c.ManagedPrincipalID == claimantID {
			return ErrInvalidManager
		}
		if err := validateManager(ctx, tx, claimantID); err != nil {
			return err
		}
		managedID = c.ManagedPrincipalID
		return upsertRelationship(ctx, tx, managedID, ManagerInput{PrincipalID: claimantID, Role: RoleGuardian}, claimantID)
	})
	if err != nil {
		return uuid.Nil, err
	}
	s.emit(ctx, EventClaimRedeemed, "redeem_claim", claimantID, managedID,
		map[string]any{"manager_principal_id": claimantID.String(), "role": RoleGuardian})
	return managedID, s.sync(ctx, "add manager", managedID, s.syncer.AddPrincipalManager(ctx, managedID, claimantID, RoleGuardian))
}

// AttachVerifiedEmail turns a managed principal into an ordinary human:
// it sets an email the caller has verified the principal controls, makes
// it the identifier, and restores default human capabilities. Manager
// relationships are kept, and may now all be removed. The actor needs
// manage_account, which guardians hold.
//
// Proving control of the address is the caller's job until SystemAuth's
// email verification (ADR-003) drives this step.
func (s *Service) AttachVerifiedEmail(ctx context.Context, actorID, managedID uuid.UUID, email string, verifiedAt time.Time) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return ErrEmailRequired
	}
	if err := s.authorizeAccount(ctx, actorID, managedID); err != nil {
		return err
	}
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		h, err := lockHuman(ctx, tx, managedID)
		if err != nil {
			return err
		}
		if h.Email != nil {
			return ErrNotManaged
		}
		taken, err := tx.Human.Query().Where(human.EmailEqualFold(email)).Exist(ctx)
		if err != nil {
			return fmt.Errorf("managedprincipal: check email: %w", err)
		}
		if taken {
			return ErrEmailInUse
		}
		if err := tx.Human.UpdateOne(h).SetEmail(email).SetEmailVerifiedAt(verifiedAt).Exec(ctx); err != nil {
			if ent.IsConstraintError(err) {
				return ErrEmailInUse
			}
			return fmt.Errorf("managedprincipal: set email: %w", err)
		}
		caps := principal.DefaultCapabilitiesForType(principal.TypeHuman)
		if err := tx.Principal.UpdateOneID(managedID).
			SetIdentifier(email).
			SetCapabilities(caps.ToMap()).
			Exec(ctx); err != nil {
			if ent.IsConstraintError(err) {
				return ErrEmailInUse
			}
			return fmt.Errorf("managedprincipal: update principal: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.emit(ctx, EventEmailAttached, "attach_email", actorID, managedID, nil)
	return nil
}

// authorizeAccount requires actorID to hold manage_account on a managed
// principal.
func (s *Service) authorizeAccount(ctx context.Context, actorID, managedID uuid.UUID) error {
	managed, err := s.client.Human.Query().
		Where(human.PrincipalID(managedID), human.EmailIsNil(), human.HasPrincipalWith(entprincipal.Active(true))).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("managedprincipal: check principal: %w", err)
	}
	if !managed {
		return ErrNotManaged
	}
	ok, err := s.authz.Can(ctx, authz.NewUserPrincipal(actorID), authz.PermManageAccount, authz.NewPrincipalResource(managedID))
	if err != nil {
		return fmt.Errorf("managedprincipal: authorize: %w", err)
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

func normalizeCode(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, strings.ToUpper(strings.TrimSpace(s)))
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}
