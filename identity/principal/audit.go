package principal

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// EventPlatformAdmin is the event type of the security event the service
// records, through WithAuditEmitter, when a human is made a platform
// administrator (action granted, also when created as one) or stops being
// one (action revoked).
const EventPlatformAdmin = "principal.platform_admin"

// WithAuditEmitter records a security event (EventPlatformAdmin) for every
// change of platform administration. The actor is the request's principal
// (requestprincipal) when there is one.
func WithAuditEmitter(e audit.Emitter) ServiceOption {
	return func(s *DefaultService) { s.audit = e }
}

// emitPlatformAdmin records a committed change of platform administration,
// so a failure to record it is logged rather than returned.
func (s *DefaultService) emitPlatformAdmin(ctx context.Context, id uuid.UUID, admin bool) {
	if s.audit == nil {
		return
	}
	action := "revoked"
	if admin {
		action = "granted"
	}
	ev := &audit.Event{
		Timestamp: time.Now().UTC(),
		EventType: EventPlatformAdmin,
		Action:    action,
		Actor:     requestprincipal.AuditActor(ctx),
		Resource:  audit.Resource{Type: "principal", ID: id},
		Context:   audit.Context{RequestID: audit.RequestID(ctx)},
		Outcome:   audit.OutcomeSuccess,
	}
	if err := s.audit.Emit(ctx, ev); err != nil {
		s.logger.ErrorContext(ctx, "principal: recording security event", "action", action, "principal_id", id, "error", err.Error())
	}
}
