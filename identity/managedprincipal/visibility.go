package managedprincipal

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	entcredential "github.com/plexusone/systemforge/identity/ent/credential"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/loginsession"
	"github.com/plexusone/systemforge/identity/ent/oauthtoken"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	"github.com/plexusone/systemforge/identity/ent/principaltoken"
)

// Audit event types for manager visibility actions.
const (
	EventTokenRevoked   = "managed_principal.login_token_revoked"
	EventSessionRevoked = "managed_principal.session_revoked"
	EventAllRevoked     = "managed_principal.all_revoked"

	revokedByManager    = "revoked by manager"
	revokedAllByManager = "all revoked by manager"
)

// SessionKind distinguishes the ways a managed principal can be signed in.
type SessionKind string

const (
	// SessionKindLogin is a SystemAuth browser login session.
	SessionKindLogin SessionKind = "login"
	// SessionKindOAuth is an OAuth token family a client holds.
	SessionKindOAuth SessionKind = "oauth"
	// SessionKindToken is a principal token family.
	SessionKindToken SessionKind = "principal_token"
)

// Session is one way a managed principal is currently signed in.
type Session struct {
	// ID identifies the session within its kind: the login session ID, or
	// the token family ID (the token ID when it has no family).
	ID   uuid.UUID   `json:"id"`
	Kind SessionKind `json:"kind"`
	// Provider is how a login session was established, such as
	// login_token.
	Provider string `json:"provider,omitempty"`
	// ClientID is the OAuth client holding an OAuth session.
	ClientID   string     `json:"client_id,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ClientIP   string     `json:"client_ip,omitempty"`
}

// authorizeCredentials requires actorID to hold manage_credentials on a
// managed principal.
func (s *Service) authorizeCredentials(ctx context.Context, actorID, managedID uuid.UUID) error {
	managed, err := s.client.Human.Query().
		Where(human.PrincipalID(managedID), hasActiveManager()).
		Exist(ctx)
	if err != nil {
		return fmt.Errorf("managedprincipal: check principal: %w", err)
	}
	if !managed {
		return ErrNotManaged
	}
	ok, err := s.authz.Can(ctx, authz.NewUserPrincipal(actorID), authz.PermManageCredentials, authz.NewPrincipalResource(managedID))
	if err != nil {
		return fmt.Errorf("managedprincipal: authorize: %w", err)
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

// ListLoginTokens returns a managed principal's usable login tokens,
// newest first. It never returns token values.
func (s *Service) ListLoginTokens(ctx context.Context, actorID, managedID uuid.UUID) ([]*credential.Credential, error) {
	if err := s.authorizeCredentials(ctx, actorID, managedID); err != nil {
		return nil, err
	}
	ids, err := s.client.Credential.Query().
		Where(liveLoginTokens(managedID, s.now())...).
		Order(ent.Desc(entcredential.FieldCreatedAt)).
		IDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: list login tokens: %w", err)
	}
	out := make([]*credential.Credential, 0, len(ids))
	for _, id := range ids {
		c, err := s.creds.GetByID(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("managedprincipal: load login token: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

// RevokeLoginToken revokes one of a managed principal's login tokens.
func (s *Service) RevokeLoginToken(ctx context.Context, actorID, managedID, credentialID uuid.UUID) error {
	if err := s.authorizeCredentials(ctx, actorID, managedID); err != nil {
		return err
	}
	n, err := s.client.Credential.Update().
		Where(
			entcredential.ID(credentialID),
			entcredential.PrincipalID(managedID),
			entcredential.TypeEQ(entcredential.TypeLoginToken),
			entcredential.Revoked(false),
		).
		SetRevoked(true).
		SetRevokedAt(s.now()).
		SetRevokedReason(revokedByManager).
		SetActive(false).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("managedprincipal: revoke login token: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	s.emit(ctx, EventTokenRevoked, "revoke_login_token", actorID, managedID,
		map[string]any{"credential_id": credentialID.String()})
	return nil
}

// ListSessions returns the ways a managed principal is signed in now:
// browser login sessions, OAuth token families, and principal token
// families.
func (s *Service) ListSessions(ctx context.Context, actorID, managedID uuid.UUID) ([]Session, error) {
	if err := s.authorizeCredentials(ctx, actorID, managedID); err != nil {
		return nil, err
	}
	now := s.now()
	var out []Session

	logins, err := s.client.LoginSession.Query().
		Where(loginsession.PrincipalID(managedID), loginsession.ExpiresAtGT(now)).
		Order(ent.Desc(loginsession.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: list login sessions: %w", err)
	}
	for _, l := range logins {
		out = append(out, Session{ID: l.ID, Kind: SessionKindLogin, Provider: l.Provider, CreatedAt: l.CreatedAt, ExpiresAt: l.ExpiresAt})
	}

	oauth, err := s.client.OAuthToken.Query().
		Where(liveOAuthTokens(managedID, now)...).
		WithApp().
		Order(ent.Desc(oauthtoken.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: list oauth tokens: %w", err)
	}
	seen := map[uuid.UUID]bool{}
	for _, t := range oauth {
		id := t.ID
		if t.FamilyID != uuid.Nil {
			id = t.FamilyID
		}
		if seen[id] {
			continue // the newest token of the family represents it
		}
		seen[id] = true
		sess := Session{ID: id, Kind: SessionKindOAuth, CreatedAt: t.CreatedAt, ExpiresAt: laterOf(t.AccessExpiresAt, t.RefreshExpiresAt), LastUsedAt: t.LastUsedAt, ClientIP: t.ClientIP}
		if t.Edges.App != nil {
			sess.ClientID = t.Edges.App.ClientID
		}
		out = append(out, sess)
	}

	tokens, err := s.client.PrincipalToken.Query().
		Where(livePrincipalTokens(managedID, now)...).
		Order(ent.Desc(principaltoken.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: list principal tokens: %w", err)
	}
	seen = map[uuid.UUID]bool{}
	for _, t := range tokens {
		id := t.ID
		if t.FamilyID != uuid.Nil {
			id = t.FamilyID
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, Session{ID: id, Kind: SessionKindToken, CreatedAt: t.CreatedAt, ExpiresAt: laterOf(t.AccessExpiresAt, t.RefreshExpiresAt), LastUsedAt: t.LastUsedAt, ClientIP: t.ClientIP})
	}
	return out, nil
}

// RevokeSession ends one session listed by ListSessions. Revoking a token
// family revokes every token in it, so its refresh token cannot renew it.
func (s *Service) RevokeSession(ctx context.Context, actorID, managedID uuid.UUID, kind SessionKind, sessionID uuid.UUID) error {
	if err := s.authorizeCredentials(ctx, actorID, managedID); err != nil {
		return err
	}
	now := s.now()
	var n int
	var change accesschange.Change
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		var err error
		switch kind {
		case SessionKindLogin:
			n, err = tx.LoginSession.Delete().
				Where(loginsession.ID(sessionID), loginsession.PrincipalID(managedID)).
				Exec(ctx)
		case SessionKindOAuth:
			n, err = tx.OAuthToken.Update().
				Where(
					oauthtoken.SubjectEQ(managedID.String()),
					oauthtoken.Revoked(false),
					oauthtoken.Or(oauthtoken.FamilyID(sessionID), oauthtoken.ID(sessionID)),
				).
				SetRevoked(true).SetRevokedAt(now).SetRevokedReason(revokedByManager).
				Save(ctx)
		case SessionKindToken:
			n, err = tx.PrincipalToken.Update().
				Where(
					principaltoken.PrincipalID(managedID),
					principaltoken.Revoked(false),
					principaltoken.Or(principaltoken.FamilyID(sessionID), principaltoken.ID(sessionID)),
				).
				SetRevoked(true).SetRevokedAt(now).SetRevokedReason(revokedByManager).
				Save(ctx)
		default:
			return fmt.Errorf("%w: session kind %q", ErrNotFound, kind)
		}
		if err != nil {
			return fmt.Errorf("managedprincipal: revoke %s session: %w", kind, err)
		}
		if n == 0 {
			return nil
		}
		// Access tokens already issued stop being honored at once (ADR-010).
		change, err = accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: managedID, Reason: accesschange.SessionsRevoked})
		return err
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	accesschange.Publish(s.accessSink, change)
	s.emit(ctx, EventSessionRevoked, "revoke_session", actorID, managedID,
		map[string]any{"kind": string(kind), "session_id": sessionID.String()})
	return nil
}

// RevokeAll revokes every login token and ends every session of a managed
// principal in one transaction.
func (s *Service) RevokeAll(ctx context.Context, actorID, managedID uuid.UUID) error {
	if err := s.authorizeCredentials(ctx, actorID, managedID); err != nil {
		return err
	}
	now := s.now()
	counts := map[string]int{}
	var change accesschange.Change
	err := s.withTx(ctx, func(tx *ent.Tx) error {
		n, err := tx.Credential.Update().
			Where(
				entcredential.PrincipalID(managedID),
				entcredential.TypeEQ(entcredential.TypeLoginToken),
				entcredential.Revoked(false),
			).
			SetRevoked(true).SetRevokedAt(now).SetRevokedReason(revokedAllByManager).SetActive(false).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("managedprincipal: revoke login tokens: %w", err)
		}
		counts["login_tokens"] = n
		if n, err = tx.LoginSession.Delete().Where(loginsession.PrincipalID(managedID)).Exec(ctx); err != nil {
			return fmt.Errorf("managedprincipal: end login sessions: %w", err)
		}
		counts["login_sessions"] = n
		if n, err = tx.OAuthToken.Update().
			Where(oauthtoken.SubjectEQ(managedID.String()), oauthtoken.Revoked(false)).
			SetRevoked(true).SetRevokedAt(now).SetRevokedReason(revokedAllByManager).
			Save(ctx); err != nil {
			return fmt.Errorf("managedprincipal: revoke oauth tokens: %w", err)
		}
		counts["oauth_tokens"] = n
		if n, err = tx.PrincipalToken.Update().
			Where(principaltoken.PrincipalID(managedID), principaltoken.Revoked(false)).
			SetRevoked(true).SetRevokedAt(now).SetRevokedReason(revokedAllByManager).
			Save(ctx); err != nil {
			return fmt.Errorf("managedprincipal: revoke principal tokens: %w", err)
		}
		counts["principal_tokens"] = n
		// Access tokens already issued stop being honored at once (ADR-010).
		change, err = accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: managedID, Reason: accesschange.SessionsRevoked})
		return err
	})
	if err != nil {
		return err
	}
	accesschange.Publish(s.accessSink, change)
	details := make(map[string]any, len(counts))
	for k, v := range counts {
		details[k] = v
	}
	s.emit(ctx, EventAllRevoked, "revoke_all", actorID, managedID, details)
	return nil
}

func liveLoginTokens(managedID uuid.UUID, now time.Time) []predicate.Credential {
	return []predicate.Credential{
		entcredential.PrincipalID(managedID),
		entcredential.TypeEQ(entcredential.TypeLoginToken),
		entcredential.Active(true),
		entcredential.Revoked(false),
		entcredential.ExpiresAtGT(now),
	}
}

func liveOAuthTokens(managedID uuid.UUID, now time.Time) []predicate.OAuthToken {
	return []predicate.OAuthToken{
		oauthtoken.SubjectEQ(managedID.String()),
		oauthtoken.Revoked(false),
		oauthtoken.Or(oauthtoken.AccessExpiresAtGT(now), oauthtoken.RefreshExpiresAtGT(now)),
	}
}

func livePrincipalTokens(managedID uuid.UUID, now time.Time) []predicate.PrincipalToken {
	return []predicate.PrincipalToken{
		principaltoken.PrincipalID(managedID),
		principaltoken.Revoked(false),
		principaltoken.Or(principaltoken.AccessExpiresAtGT(now), principaltoken.RefreshExpiresAtGT(now)),
	}
}

func laterOf(a time.Time, b *time.Time) time.Time {
	if b != nil && b.After(a) {
		return *b
	}
	return a
}
