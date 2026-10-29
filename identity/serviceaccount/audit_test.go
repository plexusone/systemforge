package serviceaccount_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/identity/serviceaccount"
)

type recordingEmitter struct{ events []audit.Event }

func (r *recordingEmitter) Emit(_ context.Context, ev *audit.Event) error {
	r.events = append(r.events, *ev)
	return nil
}

func TestAuditEvents(t *testing.T) {
	f := newFixture(t)
	rec := &recordingEmitter{}
	svc, err := serviceaccount.New(serviceaccount.Config{
		Client:     f.db,
		Principals: principal.NewService(f.db),
		Roles:      f.roles,
		Audit:      rec,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	acct, err := svc.Create(ctx, serviceaccount.CreateInput{OrganizationID: f.org.ID, Name: "ci", CreatedBy: f.owner})
	if err != nil {
		t.Fatal(err)
	}
	k, err := svc.AddKey(ctx, acct.ID, serviceaccount.KeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func() error{
		func() error { return svc.GrantRole(ctx, acct.ID, "billing", "viewer", f.owner) },
		func() error { return svc.RemoveRole(ctx, acct.ID, "billing", f.owner) },
		func() error { return svc.RevokeKey(ctx, acct.ID, k.KeyID, "rotated") },
		func() error { return svc.Disable(ctx, acct.ID, f.owner) },
		func() error { return svc.Enable(ctx, acct.ID, f.owner) },
		func() error { return svc.Delete(ctx, acct.ID, f.owner) },
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	var actions []string
	for _, ev := range rec.events {
		if ev.EventType != serviceaccount.EventServiceAccount || ev.Resource.ID != acct.ID || ev.Outcome != audit.OutcomeSuccess {
			t.Errorf("event: %+v", ev)
		}
		actions = append(actions, ev.Action)
	}
	want := "created key_added role_granted role_removed key_revoked disabled enabled deleted"
	if got := strings.Join(actions, " "); got != want {
		t.Errorf("actions = %q, want %q", got, want)
	}
	if rec.events[0].Actor.ID != f.owner {
		t.Errorf("created by = %v", rec.events[0].Actor)
	}
	raw, err := json.Marshal(rec.events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "PUBLIC KEY") {
		t.Error("an event carries key material")
	}
}
