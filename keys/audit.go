package keys

import (
	"context"
	"fmt"
	"log/slog"

	kfaudit "github.com/plexusone/keyforge/audit"

	sfaudit "github.com/plexusone/systemforge/contract/audit"
)

// auditSink sends keyforge lifecycle events to the platform audit trail.
type auditSink struct {
	store sfaudit.Store
}

func (s auditSink) Emit(ctx context.Context, e kfaudit.Event) error {
	ev := &sfaudit.Event{
		Timestamp: e.Time,
		EventType: "keys",
		Action:    string(e.Action),
		Actor:     sfaudit.Actor{Type: "service", Identifier: "keyforge"},
		Resource:  sfaudit.Resource{Type: "key", Identifier: keyIdentifier(e)},
		Outcome:   outcome(e.Outcome),
		Details: map[string]any{
			"purpose":  e.Purpose,
			"outcome":  string(e.Outcome),
			"event_id": e.ID,
		},
	}
	if e.Actor != "" {
		ev.Actor = sfaudit.Actor{Type: "human", Identifier: e.Actor}
	}
	if e.Reason != "" {
		ev.Details["reason"] = e.Reason
	}
	if e.DEKID != "" {
		ev.Details["dek_id"] = e.DEKID
	}
	if _, err := s.store.Record(ctx, ev); err != nil {
		return fmt.Errorf("keys: recording %s: %w", e.Action, err)
	}
	return nil
}

func keyIdentifier(e kfaudit.Event) string {
	if e.KEKID == "" {
		return e.Purpose
	}
	return fmt.Sprintf("%s/v%d", e.KEKID, e.Version)
}

// outcome maps keyforge's outcomes onto the platform's success and failure;
// the original is kept in the event details.
func outcome(o kfaudit.Outcome) string {
	if o == kfaudit.Success || o == kfaudit.Pending {
		return "success"
	}
	return "failure"
}

// logSink logs keyforge lifecycle events when no audit store is configured,
// so they are not discarded.
type logSink struct {
	logger *slog.Logger
}

func (s logSink) Emit(ctx context.Context, e kfaudit.Event) error {
	attrs := []any{
		"action", string(e.Action),
		"outcome", string(e.Outcome),
		"purpose", e.Purpose,
		"event_id", e.ID,
	}
	if e.Actor != "" {
		attrs = append(attrs, "actor", e.Actor)
	}
	if e.DEKID != "" {
		attrs = append(attrs, "dek_id", e.DEKID)
	}
	if e.Reason != "" {
		attrs = append(attrs, "reason", e.Reason)
	}
	s.logger.InfoContext(ctx, "key lifecycle event", attrs...)
	return nil
}
