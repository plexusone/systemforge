package organization

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// EventMembership is the event type of the security events the service
// records for membership changes through WithAuditEmitter. The action is
// added, updated or removed.
const EventMembership = "organization.membership"

// WithAuditEmitter records a security event (EventMembership) for every
// membership added, updated (role or active state) or removed. The actor is
// the request's principal (requestprincipal) when there is one.
func WithAuditEmitter(e audit.Emitter) ServiceOption {
	return func(s *DefaultService) { s.audit = e }
}

// emitMembership records a membership change that has committed, so a
// failure to record it is logged rather than returned.
func (s *DefaultService) emitMembership(ctx context.Context, action string, orgID, principalID uuid.UUID, details map[string]any) {
	if s.audit == nil {
		return
	}
	if details == nil {
		details = map[string]any{}
	}
	details["organization_id"] = orgID.String()
	details["principal_id"] = principalID.String()
	tenant := orgID
	ev := &audit.Event{
		Timestamp: time.Now().UTC(),
		EventType: EventMembership,
		Action:    action,
		Actor:     requestprincipal.AuditActor(ctx),
		Resource:  audit.Resource{Type: "membership", ID: principalID},
		Context:   audit.Context{TenantID: &tenant, RequestID: audit.RequestID(ctx)},
		Outcome:   audit.OutcomeSuccess,
		Details:   details,
	}
	if err := s.audit.Emit(ctx, ev); err != nil {
		s.logger.ErrorContext(ctx, "organization: recording security event", "action", action, "organization_id", orgID, "principal_id", principalID, "error", err.Error())
	}
}
