package systemauth

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// clientAllowsSubject reports whether clientID may receive authorization
// for subject. A managed principal is only ever authorized for a client
// that allows managed principals (ADR-005 invariant 3): the browser login
// session is shared by every client, so the check made when a login token
// is exchanged for one client does not cover the others. Subjects that are
// not principals of the login directory, and everyone who is not managed,
// are allowed.
func (s *Server) clientAllowsSubject(ctx context.Context, subject, clientID string) (bool, error) {
	if s.social == nil || s.social.directory == nil || subject == "" {
		return true, nil
	}
	id, err := uuid.Parse(subject)
	if err != nil {
		return true, nil
	}
	p, err := s.social.directory.GetPrincipal(ctx, id)
	if errors.Is(err, ErrPrincipalNotFound) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("loading principal %s: %w", id, err)
	}
	if !p.Managed {
		return true, nil
	}
	return s.ManagedPrincipalsAllowed(ctx, clientID)
}
