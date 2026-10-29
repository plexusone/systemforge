package principal_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

type recordingEmitter struct{ events []audit.Event }

func (r *recordingEmitter) Emit(_ context.Context, ev *audit.Event) error {
	r.events = append(r.events, *ev)
	return nil
}

func TestPlatformAdminAuditEvents(t *testing.T) {
	rec := &recordingEmitter{}
	svc, _, _ := newService(t, principal.WithAuditEmitter(rec))
	operator := uuid.New()
	ctx := requestprincipal.WithPrincipal(context.Background(), &requestprincipal.RequestPrincipal{PrincipalID: operator.String(), Type: requestprincipal.TypeHuman})

	h, err := svc.CreateHuman(ctx, principal.CreateHumanInput{Email: "kim@example.com", DisplayName: "Kim", IsPlatformAdmin: true})
	if err != nil {
		t.Fatal(err)
	}
	no, yes := false, true
	if _, err := svc.UpdateHuman(ctx, h.ID, principal.UpdateHumanInput{IsPlatformAdmin: &no}); err != nil {
		t.Fatal(err)
	}
	// Setting the flag it already has records nothing.
	if _, err := svc.UpdateHuman(ctx, h.ID, principal.UpdateHumanInput{IsPlatformAdmin: &no}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateHuman(ctx, h.ID, principal.UpdateHumanInput{IsPlatformAdmin: &yes}); err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, ev := range rec.events {
		if ev.EventType != principal.EventPlatformAdmin || ev.Resource.ID != h.ID || ev.Actor.ID != operator {
			t.Errorf("event: %+v", ev)
		}
		actions = append(actions, ev.Action)
	}
	if len(actions) != 3 || actions[0] != "granted" || actions[1] != "revoked" || actions[2] != "granted" {
		t.Errorf("actions = %v", actions)
	}
}
