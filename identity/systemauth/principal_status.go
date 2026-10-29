package systemauth

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/ent"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/internal/oauthcore"
)

// PrincipalStatus tells whether a token's subject may still use it. Every
// Storage implements it. SystemAuth checks it whenever a token is used or
// refreshed, so deactivating or deleting a principal takes effect
// immediately, however it was deactivated or deleted.
//
// Principals are the sole identity root (ADR-004): the subject of every
// token issued for an end-user is a principal ID, which is why a
// SessionProvider must return principal IDs.
type PrincipalStatus interface {
	// PrincipalActive reports whether the principal named by subject is
	// active. A subject that is not a principal ID (a UUID), or names no
	// principal this storage holds, is inactive, so the tokens of a
	// deleted principal stop working as those of a deactivated one do. An
	// empty subject is a client's own token (client credentials), which no
	// principal owns, and reports true.
	PrincipalActive(ctx context.Context, subject string) (bool, error)
}

// PrincipalActive implements PrincipalStatus for the principals in the
// identity database.
func (s *EntStorage) PrincipalActive(ctx context.Context, subject string) (bool, error) {
	if subject == "" {
		return true, nil
	}
	id, err := uuid.Parse(subject)
	if err != nil {
		return false, nil
	}
	p, err := s.db.Principal.Query().Where(entprincipal.ID(id)).Select(entprincipal.FieldActive).Only(ctx)
	if ent.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking principal %s: %w", id, err)
	}
	return p.Active, nil
}

// PrincipalActive implements PrincipalStatus for the humans the memory
// storage holds; any other non-empty subject is inactive.
func (s *MemoryStorage) PrincipalActive(_ context.Context, subject string) (bool, error) {
	if subject == "" {
		return true, nil
	}
	id, err := uuid.Parse(subject)
	if err != nil {
		return false, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if h, ok := s.humans[id]; ok {
		return h.Active, nil
	}
	return false, nil
}

// subjectActive reports whether a token subject may use its token. A token
// without a subject (client credentials) is the client's own.
func (s *Server) subjectActive(ctx context.Context, subject string) (bool, error) {
	if subject == "" {
		return true, nil
	}
	return s.storage.PrincipalActive(ctx, subject)
}

// introspect validates a token and requires its principal to be active. A
// token of an inactive principal is reported as inactive, and its token
// family is revoked so later uses fail without the check.
func (s *Server) introspect(ctx context.Context, token string, tokenType fosite.TokenType, session fosite.Session) (fosite.AccessRequester, error) {
	_, ar, err := s.oauth2.IntrospectToken(ctx, token, tokenType, session)
	if err != nil {
		return nil, err
	}
	if err := s.requireActiveSubject(ctx, ar); err != nil {
		return nil, err
	}
	return ar, nil
}

// requireActiveSubject returns fosite.ErrInactiveToken, after revoking the
// request's token family, when the request's principal is no longer
// active.
func (s *Server) requireActiveSubject(ctx context.Context, ar fosite.Requester) error {
	active, err := s.subjectActive(ctx, sessionSubject(ar.GetSession()))
	if err != nil {
		return fosite.ErrServerError.WithWrap(err)
	}
	if active {
		return nil
	}
	if err := s.storage.RevokeRefreshToken(ctx, ar.GetID()); err != nil {
		LoggerFromContext(ctx).ErrorContext(ctx, "revoking tokens of an inactive principal", "request_id", ar.GetID(), oauthcore.ErrorAttr(ctx, LoggerFromContext(ctx), err))
	}
	return fosite.ErrInactiveToken.WithHint("The principal is no longer active.")
}

var (
	_ PrincipalStatus = (*EntStorage)(nil)
	_ PrincipalStatus = (*MemoryStorage)(nil)
)
