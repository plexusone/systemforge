package delegation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
)

type fixture struct {
	t   *testing.T
	db  *ent.Client
	svc Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return &fixture{t: t, db: db, svc: NewService(db)}
}

func (f *fixture) human(canDelegate bool) uuid.UUID {
	f.t.Helper()
	p, err := f.db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").
		SetDisplayName("Human").SetCapabilities(map[string]bool{"can_delegate": canDelegate}).Save(context.Background())
	if err != nil {
		f.t.Fatalf("human: %v", err)
	}
	return p.ID
}

func (f *fixture) agent(canDelegate bool) uuid.UUID {
	f.t.Helper()
	ctx := context.Background()
	p, err := f.db.Principal.Create().SetType(entprincipal.TypeAgent).SetIdentifier("agent-" + uuid.NewString()).
		SetDisplayName("Agent").SetCapabilities(map[string]bool{"can_delegate": canDelegate}).Save(ctx)
	if err != nil {
		f.t.Fatalf("agent principal: %v", err)
	}
	if _, err := f.db.Agent.Create().SetPrincipalID(p.ID).SetModelID("model").Save(ctx); err != nil {
		f.t.Fatalf("agent: %v", err)
	}
	return p.ID
}

func (f *fixture) delegate(from, to uuid.UUID, c Constraints) {
	f.t.Helper()
	if _, err := f.svc.CreateDelegation(context.Background(), CreateInput{DelegatorID: from, DelegateID: to, Constraints: c}); err != nil {
		f.t.Fatalf("CreateDelegation: %v", err)
	}
}

func (f *fixture) allowed(principalID uuid.UUID, action, resource string) bool {
	f.t.Helper()
	v, err := f.svc.ValidateAction(context.Background(), principalID, action, resource)
	if err != nil {
		f.t.Fatalf("ValidateAction: %v", err)
	}
	return v.Allowed
}

func TestDelegatedActions(t *testing.T) {
	f := newFixture(t)
	person := f.human(true)
	bot := f.agent(false)
	f.delegate(person, bot, Constraints{AllowedActions: []string{"read"}, AllowedResources: []string{"project/*"}, AllowedScopes: []string{"files"}})

	if !f.allowed(person, "delete", "anything") {
		t.Error("a person acting for themselves was refused")
	}
	if !f.allowed(bot, "read", "project/1") {
		t.Error("an allowed action was refused")
	}
	if f.allowed(bot, "write", "project/1") {
		t.Error("an action outside the delegation was allowed")
	}
	if f.allowed(bot, "read", "billing/1") {
		t.Error("a resource outside the delegation was allowed")
	}

	chain, err := f.svc.GetChain(context.Background(), bot)
	if err != nil || chain.Depth() != 2 || chain.Root().PrincipalID != person || chain.Current().PrincipalID != bot {
		t.Fatalf("chain = %+v, %v", chain, err)
	}
	if got := chain.EffectiveConstraints.AllowedScopes; len(got) != 1 || got[0] != "files" {
		t.Errorf("scopes were not stored: %v", got)
	}
}

// TestDisjointConstraintsAllowNothing verifies that constraints that do
// not overlap leave nothing allowed, rather than everything.
func TestDisjointConstraintsAllowNothing(t *testing.T) {
	f := newFixture(t)
	person := f.human(true)
	parent := f.agent(true)
	child := f.agent(false)
	f.delegate(person, parent, Constraints{AllowedActions: []string{"read"}})
	f.delegate(parent, child, Constraints{AllowedActions: []string{"write"}})

	for _, action := range []string{"read", "write", "delete"} {
		if f.allowed(child, action, "doc/1") {
			t.Errorf("%s allowed through disjoint delegations", action)
		}
	}
	chain, err := f.svc.GetChain(context.Background(), child)
	if err != nil || chain.EffectiveConstraints.AllowedActions == nil || len(chain.EffectiveConstraints.AllowedActions) != 0 {
		t.Errorf("effective actions = %#v, %v; want an empty restriction", chain.EffectiveConstraints.AllowedActions, err)
	}
}

func TestDelegationExpires(t *testing.T) {
	f := newFixture(t)
	person := f.human(true)
	bot := f.agent(false)
	past := time.Now().Add(-time.Minute)
	f.delegate(person, bot, Constraints{ExpiresAt: &past})
	if f.allowed(bot, "read", "doc/1") {
		t.Error("an expired delegation allowed an action")
	}
	future := time.Now().Add(time.Hour)
	f.delegate(person, bot, Constraints{ExpiresAt: &future})
	if !f.allowed(bot, "read", "doc/1") {
		t.Error("a current delegation was refused")
	}
}

// TestRevokedAgentActsForNoOne verifies that revoking a delegation leaves
// the agent with no authority, not unlimited authority.
func TestRevokedAgentActsForNoOne(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	person := f.human(true)
	bot := f.agent(false)
	f.delegate(person, bot, Constraints{AllowedActions: []string{"read"}})

	if err := f.svc.RevokeDelegation(ctx, f.human(true), bot, "wrong delegator"); !errors.Is(err, ErrDelegatorMismatch) {
		t.Errorf("revoke by another principal = %v", err)
	}
	if err := f.svc.RevokeDelegation(ctx, person, bot, "done"); err != nil {
		t.Fatalf("RevokeDelegation: %v", err)
	}
	for _, action := range []string{"read", "write"} {
		if f.allowed(bot, action, "doc/1") {
			t.Errorf("%s allowed for a revoked agent", action)
		}
	}
	if f.allowed(f.agent(false), "read", "doc/1") {
		t.Error("an agent that was never delegated to was allowed")
	}
}

func TestInactivePrincipalsBreakTheChain(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	person := f.human(true)
	bot := f.agent(false)
	f.delegate(person, bot, Constraints{})
	if !f.allowed(bot, "read", "doc/1") {
		t.Fatal("delegated agent refused")
	}
	if err := f.db.Principal.UpdateOneID(person).SetActive(false).Exec(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if f.allowed(bot, "read", "doc/1") {
		t.Error("an agent acting for a deactivated person was allowed")
	}
}

func TestCreateDelegationRefusals(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	person := f.human(true)
	cannot := f.human(false)
	other := f.human(true)
	a := f.agent(true)
	b := f.agent(true)

	for name, tc := range map[string]struct {
		in   CreateInput
		want error
	}{
		"lacks can_delegate": {CreateInput{DelegatorID: cannot, DelegateID: a}, ErrCannotDelegate},
		"delegate not agent": {CreateInput{DelegatorID: person, DelegateID: other}, ErrNotAgent},
		"self":               {CreateInput{DelegatorID: a, DelegateID: a}, ErrSelfDelegation},
		"unknown delegator":  {CreateInput{DelegatorID: uuid.New(), DelegateID: a}, ErrNotFound},
		"unknown delegate":   {CreateInput{DelegatorID: person, DelegateID: uuid.New()}, ErrNotFound},
	} {
		if _, err := f.svc.CreateDelegation(ctx, tc.in); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}

	// A cycle is refused: a -> b, then b -> a.
	f.delegate(person, a, Constraints{})
	f.delegate(a, b, Constraints{})
	if _, err := f.svc.CreateDelegation(ctx, CreateInput{DelegatorID: b, DelegateID: a}); !errors.Is(err, ErrCircularDelegation) {
		t.Errorf("cycle = %v, want ErrCircularDelegation", err)
	}

	// An inactive delegator cannot delegate.
	if err := f.db.Principal.UpdateOneID(other).SetActive(false).Exec(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if _, err := f.svc.CreateDelegation(ctx, CreateInput{DelegatorID: other, DelegateID: f.agent(false)}); !errors.Is(err, ErrCannotDelegate) {
		t.Errorf("inactive delegator = %v", err)
	}

	links, err := f.svc.ListDelegations(ctx, person)
	if err != nil || len(links) != 1 || links[0].PrincipalID != a {
		t.Errorf("ListDelegations = %+v, %v", links, err)
	}
}

func TestIntersectConstraints(t *testing.T) {
	hour, day := time.Hour, 24*time.Hour
	soon, later := time.Now().Add(hour), time.Now().Add(day)
	got := intersectConstraints(
		Constraints{AllowedActions: []string{"read", "write"}, MaxTokenLifetime: day, ExpiresAt: &later},
		Constraints{AllowedActions: []string{"write"}, AllowedResources: []string{"a/*"}, MaxTokenLifetime: hour, ExpiresAt: &soon, RequiresConfirmation: true},
	)
	if len(got.AllowedActions) != 1 || got.AllowedActions[0] != "write" || len(got.AllowedResources) != 1 ||
		got.MaxTokenLifetime != hour || !got.ExpiresAt.Equal(soon) || !got.RequiresConfirmation || got.AllowedScopes != nil {
		t.Errorf("intersection = %+v", got)
	}
}
