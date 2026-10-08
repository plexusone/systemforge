package credential

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

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/credential"
)

const (
	// LoginTokenPrefix starts every login token. Tokens use only uppercase
	// letters and digits so a QR code can encode them in alphanumeric mode.
	LoginTokenPrefix = "SFLT"
	// LoginTokenBytes is the number of random bytes in a login token.
	LoginTokenBytes = 32
	// loginTokenIDLen is the length of the stored, displayable prefix.
	loginTokenIDLen = len(LoginTokenPrefix) + 8

	// DefaultLoginTokenTTL is the platform default lifetime of a reusable
	// login token.
	DefaultLoginTokenTTL = 30 * 24 * time.Hour
	// DefaultLoginTokenMaxTTL is the platform ceiling on any login token's
	// lifetime: one school year plus slack.
	DefaultLoginTokenMaxTTL = 400 * 24 * time.Hour
	// DefaultSingleUseLoginTokenTTL is the default lifetime of a
	// single-use login token.
	DefaultSingleUseLoginTokenTTL = 20 * time.Minute

	metaIssuedBy  = "issued_by"
	metaSingleUse = "single_use"
)

var (
	// ErrInvalidLoginToken is returned for every login token that cannot
	// be used: unknown, malformed, expired, revoked, inactive, or already
	// used. Callers must not distinguish these cases to the presenter.
	ErrInvalidLoginToken = errors.New("credential: invalid login token")
	// ErrInvalidExpiry is returned when a requested expiry is not in the
	// future.
	ErrInvalidExpiry = errors.New("credential: login token expiry must be in the future")
)

var loginTokenEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// IssueLoginTokenInput describes a login token to issue.
type IssueLoginTokenInput struct {
	// PrincipalID is the managed principal the token signs in.
	PrincipalID uuid.UUID
	// IssuedBy is the manager issuing the token.
	IssuedBy uuid.UUID
	// ExpiresAt is required; resolve it with LoginTokenPolicy.ExpiresAt.
	ExpiresAt time.Time
	// SingleUse revokes the token on its first successful use.
	SingleUse bool
	// Name is an optional label, such as the device or card it is for.
	Name string
}

// GeneratedLoginToken is a newly issued login token. PlainToken is
// available only here; the database stores its hash.
type GeneratedLoginToken struct {
	Credential *Credential `json:"credential"`
	PlainToken string      `json:"plain_token"`
	Prefix     string      `json:"prefix"`
}

// LoginTokenPolicy bounds login token lifetimes. Zero fields use the
// platform defaults.
type LoginTokenPolicy struct {
	// DefaultTTL applies to reusable tokens issued without an explicit
	// expiry. A client may set its own, for example a school year.
	DefaultTTL time.Duration
	// MaxTTL caps every token's lifetime.
	MaxTTL time.Duration
	// SingleUseTTL applies to single-use tokens issued without an
	// explicit expiry.
	SingleUseTTL time.Duration
}

// ExpiresAt resolves a token's expiry: the requested time if given, else
// the single-use or default lifetime, never beyond MaxTTL. clamped reports
// that the result was cut to MaxTTL, which callers should log.
func (p LoginTokenPolicy) ExpiresAt(now time.Time, requested *time.Time, singleUse bool) (exp time.Time, clamped bool, err error) {
	defaultTTL, maxTTL, singleUseTTL := p.DefaultTTL, p.MaxTTL, p.SingleUseTTL
	if defaultTTL <= 0 {
		defaultTTL = DefaultLoginTokenTTL
	}
	if maxTTL <= 0 {
		maxTTL = DefaultLoginTokenMaxTTL
	}
	if singleUseTTL <= 0 {
		singleUseTTL = DefaultSingleUseLoginTokenTTL
	}

	switch {
	case requested != nil:
		if !requested.After(now) {
			return time.Time{}, false, ErrInvalidExpiry
		}
		exp = *requested
	case singleUse:
		exp = now.Add(singleUseTTL)
	default:
		exp = now.Add(defaultTTL)
	}
	if limit := now.Add(maxTTL); exp.After(limit) {
		return limit, true, nil
	}
	return exp, false, nil
}

// IssueLoginToken creates a login token credential and returns its plain
// value once.
func (s *DefaultService) IssueLoginToken(ctx context.Context, input IssueLoginTokenInput) (*GeneratedLoginToken, error) {
	if input.ExpiresAt.IsZero() {
		return nil, ErrInvalidExpiry
	}
	randomBytes := make([]byte, LoginTokenBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	plain := LoginTokenPrefix + loginTokenEncoding.EncodeToString(randomBytes)
	prefix := plain[:loginTokenIDLen]

	create := s.client.Credential.Create().
		SetPrincipalID(input.PrincipalID).
		SetType(credential.TypeLoginToken).
		SetIdentifier(prefix).
		SetSecretHash(hashLoginToken(plain)).
		SetActive(true).
		SetExpiresAt(input.ExpiresAt).
		SetMetadata(map[string]any{
			metaIssuedBy:  input.IssuedBy.String(),
			metaSingleUse: input.SingleUse,
		})
	if input.Name != "" {
		create.SetName(input.Name)
	}
	cred, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create login token credential: %w", err)
	}
	return &GeneratedLoginToken{
		Credential: entCredentialToModel(cred),
		PlainToken: plain,
		Prefix:     prefix,
	}, nil
}

// VerifyLoginToken returns the credential for a usable login token and
// records its use. A single-use token is revoked atomically, so it
// succeeds at most once even under concurrent presentation. Every
// unusable token yields ErrInvalidLoginToken.
func (s *DefaultService) VerifyLoginToken(ctx context.Context, plainToken, ip string) (*Credential, error) {
	plain := normalizeLoginToken(plainToken)
	if len(plain) <= loginTokenIDLen || !strings.HasPrefix(plain, LoginTokenPrefix) {
		return nil, ErrInvalidLoginToken
	}

	cred, err := s.client.Credential.Query().
		Where(
			credential.TypeEQ(credential.TypeLoginToken),
			credential.IdentifierEQ(plain[:loginTokenIDLen]),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrInvalidLoginToken
	}
	if err != nil {
		return nil, fmt.Errorf("failed to look up login token: %w", err)
	}

	want, err := hex.DecodeString(cred.SecretHash)
	if err != nil {
		return nil, fmt.Errorf("corrupt login token hash for credential %s: %w", cred.ID, err)
	}
	got := sha256.Sum256([]byte(plain))
	if subtle.ConstantTimeCompare(got[:], want) != 1 {
		return nil, ErrInvalidLoginToken
	}
	now := time.Now()
	if !cred.Active || cred.Revoked || cred.ExpiresAt == nil || !cred.ExpiresAt.After(now) {
		return nil, ErrInvalidLoginToken
	}

	// The conditions are repeated in the update so a token revoked or
	// used between the read and the write is not accepted.
	update := s.client.Credential.Update().
		Where(
			credential.ID(cred.ID),
			credential.Active(true),
			credential.Revoked(false),
		).
		SetLastUsedAt(now)
	if ip != "" {
		update.SetLastUsedIP(ip)
	}
	if singleUseMeta(cred.Metadata) {
		update.SetRevoked(true).SetRevokedAt(now).SetRevokedReason("used").SetActive(false)
	}
	n, err := update.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to record login token use: %w", err)
	}
	if n != 1 {
		return nil, ErrInvalidLoginToken
	}

	updated, err := s.client.Credential.Get(ctx, cred.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to reload login token: %w", err)
	}
	return entCredentialToModel(updated), nil
}

// LoginTokenIssuedBy returns the manager that issued a login token, or
// uuid.Nil when none is recorded.
func LoginTokenIssuedBy(c *Credential) (uuid.UUID, error) {
	v, ok := c.Metadata[metaIssuedBy]
	if !ok {
		return uuid.Nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return uuid.Nil, fmt.Errorf("credential %s: %s is %T, not a string", c.ID, metaIssuedBy, v)
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("credential %s: %s: %w", c.ID, metaIssuedBy, err)
	}
	return id, nil
}

// LoginTokenSingleUse reports whether a login token is single-use.
func LoginTokenSingleUse(c *Credential) bool {
	return singleUseMeta(c.Metadata)
}

// singleUseMeta reads the single-use flag; a missing flag means reusable.
func singleUseMeta(m map[string]any) bool {
	singleUse, ok := m[metaSingleUse].(bool)
	return ok && singleUse
}

// normalizeLoginToken accepts a token typed by hand: case-insensitive,
// with spaces or hyphens used to group characters.
func normalizeLoginToken(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, strings.ToUpper(strings.TrimSpace(s)))
}

func hashLoginToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}
