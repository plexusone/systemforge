// Package scimtoken issues, rotates, revokes and authenticates the bearer
// tokens a tenant organization's identity provider presents to the SCIM
// API.
//
// Each token belongs to one organization. Only a SHA-256 hash of a token is
// stored; the plaintext is returned once, when the token is issued.
//
// Rotation keeps a rollback: issuing token N leaves the previous token N-1
// valid and revokes N-2 and older in the same transaction, so the identity
// provider can be switched to N and, if that fails, left on N-1. Revoking N
// ends the overlap early or rolls back a bad N, making N-1 current again.
// Authenticate accepts at most the two newest unrevoked, unexpired tokens
// of an organization.
package scimtoken

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/organization"
	entscimtoken "github.com/plexusone/systemforge/identity/ent/scimtoken"
	"github.com/plexusone/systemforge/session/clientaddr"
)

// MaxValid is the number of tokens an organization may hold valid at once:
// the current token and the previous one.
const MaxValid = 2

// DefaultLastUsedInterval is how often a token's last use is written to
// the database at most.
const DefaultLastUsedInterval = time.Minute

// Errors returned by the service.
var (
	// ErrInvalidToken is returned by Authenticate for a token that is
	// malformed, unknown, revoked, expired, superseded, or whose
	// organization is gone. Callers answer it with 401 and do not tell the
	// cases apart.
	ErrInvalidToken = errors.New("scimtoken: invalid token")
	// ErrForbidden is returned when the actor may not manage the
	// organization's SCIM tokens.
	ErrForbidden = errors.New("scimtoken: forbidden")
	// ErrNotFound is returned when the token does not exist in the
	// organization.
	ErrNotFound = errors.New("scimtoken: token not found")
	// ErrOrganizationNotFound is returned when the organization does not
	// exist or is deleted.
	ErrOrganizationNotFound = errors.New("scimtoken: organization not found")
	// ErrTokenExists is returned by Issue when the organization already
	// holds a valid token; use Rotate.
	ErrTokenExists = errors.New("scimtoken: organization already has a SCIM token; rotate it instead")
	// ErrConflict is returned when another issue or rotation for the same
	// organization committed first. Retry if a further rotation is still
	// wanted.
	ErrConflict = errors.New("scimtoken: concurrent rotation for this organization")
)

// Status describes a token's standing.
type Status string

// Token statuses.
const (
	// StatusCurrent is the newest valid token.
	StatusCurrent Status = "current"
	// StatusPrevious is the valid token before the current one, kept so
	// the identity provider can be rolled back.
	StatusPrevious Status = "previous"
	// StatusSuperseded is an unrevoked, unexpired token older than the
	// previous one. Authenticate refuses it.
	StatusSuperseded Status = "superseded"
	// StatusExpired is a token past its expiry.
	StatusExpired Status = "expired"
	// StatusRevoked is a revoked token.
	StatusRevoked Status = "revoked"
)

// Token is a token's metadata. It never carries the token or its hash.
type Token struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	Generation     int        `json:"generation"`
	Prefix         string     `json:"prefix"`
	Description    string     `json:"description,omitempty"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	RevokedBy      *uuid.UUID `json:"revoked_by,omitempty"`
	Status         Status     `json:"status"`
}

// Issued is a newly issued token. Token is the plaintext, available only
// here; hand it to the identity provider and do not store it.
type Issued struct {
	Token    string `json:"token"`
	Metadata Token  `json:"metadata"`
	// Revoked lists the tokens the rotation revoked (N-2 and older).
	Revoked []uuid.UUID `json:"revoked,omitempty"`
}

// IssueOptions describe a new token.
type IssueOptions struct {
	// Description is an optional note, such as the identity provider's
	// name.
	Description string
	// ExpiresIn bounds the token's lifetime. Zero means no expiry.
	ExpiresIn time.Duration
}

// Option configures a Service.
type Option func(*Service)

// WithAuthorizer sets the authorizer that decides who may issue, rotate,
// revoke and list an organization's tokens: holders of
// authz.PermOrgSettings on the organization (its owners and admins) and,
// when the authorizer implements authz.PlatformAuthorizer, platform
// administrators. Without it every management call is refused.
func WithAuthorizer(a authz.Authorizer) Option {
	return func(s *Service) { s.authz = a }
}

// WithAuditEmitter records issue, rotate and revoke events and
// authentication failures. Events never carry a token or its hash.
func WithAuditEmitter(e audit.Emitter) Option {
	return func(s *Service) { s.audit = e }
}

// WithLogger sets the logger. Default: slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithClientAddress sets how the client address recorded in audit events
// is found (see clientaddr). Default: the direct peer.
func WithClientAddress(res *clientaddr.Resolver) Option {
	return func(s *Service) { s.clientAddr = res }
}

// WithLastUsedInterval sets how often a token's last use is written at
// most. Default: DefaultLastUsedInterval.
func WithLastUsedInterval(d time.Duration) Option {
	return func(s *Service) {
		if d > 0 {
			s.lastUsedInterval = d
		}
	}
}

// WithClock sets the time source, for tests.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// Service manages SCIM tokens in the identity database.
type Service struct {
	client           *ent.Client
	authz            authz.Authorizer
	audit            audit.Emitter
	logger           *slog.Logger
	lastUsedInterval time.Duration
	now              func() time.Time
	clientAddr       *clientaddr.Resolver
}

// New returns a Service over client.
func New(client *ent.Client, opts ...Option) *Service {
	s := &Service{
		client:           client,
		logger:           slog.Default(),
		lastUsedInterval: DefaultLastUsedInterval,
		now:              time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Issue issues the organization's first token. It returns ErrTokenExists
// when the organization already holds a valid token.
func (s *Service) Issue(ctx context.Context, actor, orgID uuid.UUID, opts IssueOptions) (*Issued, error) {
	return s.issue(ctx, actor, orgID, opts, false)
}

// Rotate issues a new current token N, keeps the previous current token
// as N-1, and revokes every older token, in one transaction. The
// plaintext of N is returned once. With no valid token it issues the
// first one. Concurrent rotations of one organization do not both commit:
// the later one returns ErrConflict.
func (s *Service) Rotate(ctx context.Context, actor, orgID uuid.UUID, opts IssueOptions) (*Issued, error) {
	return s.issue(ctx, actor, orgID, opts, true)
}

func (s *Service) issue(ctx context.Context, actor, orgID uuid.UUID, opts IssueOptions, rotate bool) (*Issued, error) {
	if opts.ExpiresIn < 0 {
		return nil, errors.New("scimtoken: ExpiresIn must not be negative")
	}
	if err := s.authorize(ctx, actor, orgID); err != nil {
		return nil, err
	}
	if err := s.requireOrganization(ctx, orgID); err != nil {
		return nil, err
	}
	plain, err := newToken()
	if err != nil {
		return nil, err
	}
	now := s.now()

	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("scimtoken: begin: %w", err)
	}
	issued, err := s.issueTx(ctx, tx, actor, orgID, plain, opts, now, rotate)
	if err != nil {
		return nil, rollback(tx, err)
	}
	if err := tx.Commit(); err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("scimtoken: commit: %w", err)
	}

	eventType, action := "scim_token.issued", "issue"
	if rotate {
		eventType, action = "scim_token.rotated", "rotate"
	}
	revoked := make([]string, 0, len(issued.Revoked))
	for _, id := range issued.Revoked {
		revoked = append(revoked, id.String())
	}
	s.emit(ctx, &audit.Event{
		EventType: eventType,
		Action:    action,
		Actor:     actorOf(actor),
		Resource:  audit.Resource{Type: "scim_token", ID: issued.Metadata.ID, Identifier: issued.Metadata.Prefix},
		Context:   audit.Context{TenantID: &orgID},
		Outcome:   "success",
		Details: map[string]any{
			"generation": issued.Metadata.Generation,
			"revoked":    revoked,
		},
	})
	return issued, nil
}

func (s *Service) issueTx(ctx context.Context, tx *ent.Tx, actor, orgID uuid.UUID, plain string, opts IssueOptions, now time.Time, rotate bool) (*Issued, error) {
	last, err := tx.ScimToken.Query().
		Where(entscimtoken.OrganizationID(orgID)).
		Order(entscimtoken.ByGeneration(sql.OrderDesc())).
		First(ctx)
	generation := 1
	switch {
	case err == nil:
		generation = last.Generation + 1
	case !ent.IsNotFound(err):
		return nil, fmt.Errorf("scimtoken: reading generation: %w", err)
	}

	// The insert claims (organization, generation). A concurrent issue or
	// rotation that read the same generation fails on the unique index,
	// so at most one of them commits. Generations are claimed in order, so
	// once the insert succeeds every older token is committed and the
	// query below sees it.
	create := tx.ScimToken.Create().
		SetOrganizationID(orgID).
		SetGeneration(generation).
		SetTokenPrefix(displayPrefix(plain)).
		SetTokenHash(hashToken(plain)).
		SetCreatedAt(now).
		SetDescription(opts.Description)
	if actor != uuid.Nil {
		create.SetCreatedBy(actor)
	}
	if opts.ExpiresIn > 0 {
		create.SetExpiresAt(now.Add(opts.ExpiresIn))
	}
	row, err := create.Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("scimtoken: storing token: %w", err)
	}

	active, err := tx.ScimToken.Query().
		Where(
			entscimtoken.OrganizationID(orgID),
			entscimtoken.RevokedAtIsNil(),
			entscimtoken.IDNEQ(row.ID),
		).
		Order(entscimtoken.ByGeneration(sql.OrderDesc())).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("scimtoken: listing tokens: %w", err)
	}
	// The newest valid token becomes N-1; everything older is revoked.
	var previous *ent.ScimToken
	for _, t := range active {
		if !expired(t, now) {
			previous = t
			break
		}
	}
	if previous != nil && !rotate {
		return nil, ErrTokenExists
	}
	var revoke []uuid.UUID
	for _, t := range active {
		if previous != nil && t.ID == previous.ID {
			continue
		}
		revoke = append(revoke, t.ID)
	}
	if len(revoke) > 0 {
		if _, err := tx.ScimToken.Update().
			Where(entscimtoken.IDIn(revoke...), entscimtoken.RevokedAtIsNil()).
			SetRevokedAt(now).
			Save(ctx); err != nil {
			return nil, fmt.Errorf("scimtoken: revoking older tokens: %w", err)
		}
	}
	md := toToken(row)
	md.Status = StatusCurrent
	return &Issued{Token: plain, Metadata: md, Revoked: revoke}, nil
}

// Revoke revokes one of the organization's tokens. Revoking the current
// token makes the previous one current: a rollback. Revoking a token that
// is already revoked does nothing.
func (s *Service) Revoke(ctx context.Context, actor, orgID, tokenID uuid.UUID) error {
	if err := s.authorize(ctx, actor, orgID); err != nil {
		return err
	}
	t, err := s.client.ScimToken.Query().
		Where(entscimtoken.ID(tokenID), entscimtoken.OrganizationID(orgID)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("scimtoken: reading token: %w", err)
	}
	if t.RevokedAt != nil {
		return nil
	}
	n, err := s.client.ScimToken.Update().
		Where(entscimtoken.ID(tokenID), entscimtoken.RevokedAtIsNil()).
		SetRevokedAt(s.now()).
		SetRevokedBy(actor).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("scimtoken: revoking token: %w", err)
	}
	if n == 0 {
		// Revoked concurrently.
		return nil
	}
	s.emit(ctx, &audit.Event{
		EventType: "scim_token.revoked",
		Action:    "revoke",
		Actor:     actorOf(actor),
		Resource:  audit.Resource{Type: "scim_token", ID: t.ID, Identifier: t.TokenPrefix},
		Context:   audit.Context{TenantID: &orgID},
		Outcome:   "success",
		Details:   map[string]any{"generation": t.Generation},
	})
	return nil
}

// List returns the organization's tokens, newest first, with their status.
func (s *Service) List(ctx context.Context, actor, orgID uuid.UUID) ([]Token, error) {
	if err := s.authorize(ctx, actor, orgID); err != nil {
		return nil, err
	}
	rows, err := s.client.ScimToken.Query().
		Where(entscimtoken.OrganizationID(orgID)).
		Order(entscimtoken.ByGeneration(sql.OrderDesc())).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("scimtoken: listing tokens: %w", err)
	}
	now := s.now()
	out := make([]Token, 0, len(rows))
	valid := 0
	for _, r := range rows {
		t := toToken(r)
		switch {
		case r.RevokedAt != nil:
			t.Status = StatusRevoked
		case expired(r, now):
			t.Status = StatusExpired
		case valid == 0:
			t.Status = StatusCurrent
			valid++
		case valid == 1:
			t.Status = StatusPrevious
			valid++
		default:
			t.Status = StatusSuperseded
		}
		out = append(out, t)
	}
	return out, nil
}

// Authenticate returns the token's metadata when token is one of the two
// newest valid tokens of an active organization, and ErrInvalidToken
// otherwise. A token's last use is written at most once per
// WithLastUsedInterval.
func (s *Service) Authenticate(ctx context.Context, token string) (*Token, error) {
	if !wellFormed(token) {
		s.authFailed(ctx, nil, "malformed")
		return nil, ErrInvalidToken
	}
	hash := hashToken(token)
	row, err := s.client.ScimToken.Query().Where(entscimtoken.TokenHash(hash)).Only(ctx)
	if ent.IsNotFound(err) {
		s.authFailed(ctx, nil, "unknown")
		return nil, ErrInvalidToken
	}
	if err != nil {
		return nil, fmt.Errorf("scimtoken: looking up token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(row.TokenHash), []byte(hash)) != 1 {
		s.authFailed(ctx, nil, "unknown")
		return nil, ErrInvalidToken
	}
	now := s.now()
	if row.RevokedAt != nil {
		s.authFailed(ctx, row, "revoked")
		return nil, ErrInvalidToken
	}
	if expired(row, now) {
		s.authFailed(ctx, row, "expired")
		return nil, ErrInvalidToken
	}
	newer, err := s.client.ScimToken.Query().
		Where(
			entscimtoken.OrganizationID(row.OrganizationID),
			entscimtoken.GenerationGT(row.Generation),
			entscimtoken.RevokedAtIsNil(),
			entscimtoken.Or(entscimtoken.ExpiresAtIsNil(), entscimtoken.ExpiresAtGT(now)),
		).
		Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("scimtoken: checking newer tokens: %w", err)
	}
	if newer >= MaxValid {
		s.authFailed(ctx, row, "superseded")
		return nil, ErrInvalidToken
	}
	active, err := s.client.Organization.Query().
		Where(organization.ID(row.OrganizationID), organization.Active(true)).
		Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("scimtoken: checking organization: %w", err)
	}
	if !active {
		s.authFailed(ctx, row, "organization_inactive")
		return nil, ErrInvalidToken
	}
	s.touch(ctx, row, now)
	t := toToken(row)
	t.Status = StatusCurrent
	if newer > 0 {
		t.Status = StatusPrevious
	}
	return &t, nil
}

// touch records the token's use when the last record is older than the
// interval. The conditional update keeps concurrent requests on several
// instances from all writing.
func (s *Service) touch(ctx context.Context, row *ent.ScimToken, now time.Time) {
	cutoff := now.Add(-s.lastUsedInterval)
	if row.LastUsedAt != nil && row.LastUsedAt.After(cutoff) {
		return
	}
	_, err := s.client.ScimToken.Update().
		Where(
			entscimtoken.ID(row.ID),
			entscimtoken.Or(entscimtoken.LastUsedAtIsNil(), entscimtoken.LastUsedAtLTE(cutoff)),
		).
		SetLastUsedAt(now).
		Save(ctx)
	if err != nil {
		// The request is authenticated; failing it over a usage
		// timestamp would turn a database hiccup into an outage.
		s.logger.WarnContext(ctx, "scimtoken: recording last use", "token_id", row.ID, "error", err)
		return
	}
	row.LastUsedAt = &now
}

// authorize requires actor to hold organization settings rights on orgID
// or to be a platform administrator.
func (s *Service) authorize(ctx context.Context, actor, orgID uuid.UUID) error {
	if actor == uuid.Nil || s.authz == nil {
		return ErrForbidden
	}
	p := authz.NewUserPrincipal(actor)
	ok, err := s.authz.Can(ctx, p, authz.PermOrgSettings, authz.NewResourceWithID(authz.ResourceTypeOrganization, orgID))
	if err != nil {
		return fmt.Errorf("scimtoken: authorize: %w", err)
	}
	if ok {
		return nil
	}
	if pa, isPA := s.authz.(authz.PlatformAuthorizer); isPA {
		admin, err := pa.IsPlatformAdmin(ctx, p)
		if err != nil {
			return fmt.Errorf("scimtoken: authorize: %w", err)
		}
		if admin {
			return nil
		}
	}
	return ErrForbidden
}

func (s *Service) requireOrganization(ctx context.Context, orgID uuid.UUID) error {
	ok, err := s.client.Organization.Query().
		Where(organization.ID(orgID), organization.Active(true)).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("scimtoken: reading organization: %w", err)
	}
	if !ok {
		return ErrOrganizationNotFound
	}
	return nil
}

// authFailed records a refused authentication. row is the token when it
// was found.
func (s *Service) authFailed(ctx context.Context, row *ent.ScimToken, reason string) {
	ev := &audit.Event{
		EventType: "scim_token.authentication_failed",
		Action:    "authenticate",
		Resource:  audit.Resource{Type: "scim_token"},
		Outcome:   "failure",
		Details:   map[string]any{"reason": reason},
	}
	if row != nil {
		orgID := row.OrganizationID
		ev.Resource.ID = row.ID
		ev.Resource.Identifier = row.TokenPrefix
		ev.Context.TenantID = &orgID
	}
	if info, ok := ctx.Value(requestInfoKey{}).(requestInfo); ok {
		ev.Context.ClientIP = info.clientIP
		ev.Context.UserAgent = info.userAgent
	}
	s.emit(ctx, ev)
}

// emit records an audit event. The change, if any, has committed, so a
// failure is logged rather than returned.
func (s *Service) emit(ctx context.Context, ev *audit.Event) {
	if s.audit == nil {
		return
	}
	if err := s.audit.Emit(ctx, ev); err != nil {
		s.logger.ErrorContext(ctx, "scimtoken: emit audit event", "event_type", ev.EventType, "error", err)
	}
}

func actorOf(id uuid.UUID) audit.Actor {
	return audit.Actor{ID: id, Type: "human"}
}

func expired(t *ent.ScimToken, now time.Time) bool {
	return t.ExpiresAt != nil && !now.Before(*t.ExpiresAt)
}

func toToken(r *ent.ScimToken) Token {
	return Token{
		ID:             r.ID,
		OrganizationID: r.OrganizationID,
		Generation:     r.Generation,
		Prefix:         r.TokenPrefix,
		Description:    r.Description,
		CreatedBy:      r.CreatedBy,
		CreatedAt:      r.CreatedAt,
		LastUsedAt:     r.LastUsedAt,
		ExpiresAt:      r.ExpiresAt,
		RevokedAt:      r.RevokedAt,
		RevokedBy:      r.RevokedBy,
	}
}

// rollback rolls tx back and returns err, joined with any rollback
// failure.
func rollback(tx *ent.Tx, err error) error {
	if rerr := tx.Rollback(); rerr != nil {
		return errors.Join(err, fmt.Errorf("scimtoken: rollback: %w", rerr))
	}
	return err
}
