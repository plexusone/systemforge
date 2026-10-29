package requestprincipal

import (
	"context"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/contract/audit"
)

// AuditActor returns the principal of the request ctx belongs to as the
// actor of an audit event. A principal ID that is not a SystemForge
// principal ID is kept as the identifier. Outside an authenticated request
// the actor is empty.
func AuditActor(ctx context.Context) audit.Actor {
	p, ok := FromContext(ctx)
	if !ok {
		return audit.Actor{}
	}
	a := audit.Actor{Type: string(p.Type)}
	if id, err := uuid.Parse(p.PrincipalID); err == nil {
		a.ID = id
	} else {
		a.Identifier = p.PrincipalID
	}
	return a
}
