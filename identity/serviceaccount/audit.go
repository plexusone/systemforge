package serviceaccount

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/contract/audit"
)

// EventServiceAccount is the event type of the security events the service
// records through Config.Audit. The action says what changed: created,
// disabled, enabled, deleted, key_added, key_revoked, role_granted or
// role_removed. No event carries key material.
const EventServiceAccount = "service_account"

// emit records a change that has committed, so a failure to record it is
// logged rather than returned.
func (s *Service) emit(ctx context.Context, action string, by, id uuid.UUID, details map[string]any) {
	if s.audit == nil {
		return
	}
	actor := audit.Actor{Type: "human"}
	if by != uuid.Nil {
		actor.ID = by
	}
	ev := &audit.Event{
		Timestamp: s.now().UTC(),
		EventType: EventServiceAccount,
		Action:    action,
		Actor:     actor,
		Resource:  audit.Resource{Type: "service_account", ID: id},
		Context:   audit.Context{RequestID: audit.RequestID(ctx)},
		Outcome:   audit.OutcomeSuccess,
		Details:   details,
	}
	if err := s.audit.Emit(ctx, ev); err != nil {
		s.logger.ErrorContext(ctx, "serviceaccount: recording security event", "action", action, "principal_id", id, "error", err.Error())
	}
}

// keyDetails describes a key in an event by its public identifiers only.
func keyDetails(k *Key) map[string]any {
	d := map[string]any{"key_id": k.KeyID, "algorithm": k.Algorithm}
	if k.ExpiresAt != nil {
		d["expires_at"] = k.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return d
}
