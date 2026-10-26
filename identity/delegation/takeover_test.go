package delegation

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// TestDelegationIsNotTakenOver verifies that a principal cannot replace
// another principal's delegation of an agent, while the delegator can
// replace its own and anyone can delegate once it is revoked.
func TestDelegationIsNotTakenOver(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	owner := f.human(true)
	intruder := f.human(true)
	bot := f.agent(false)
	f.delegate(owner, bot, Constraints{AllowedActions: []string{"read"}})

	if _, err := f.svc.CreateDelegation(ctx, CreateInput{DelegatorID: intruder, DelegateID: bot, Constraints: Constraints{AllowedActions: []string{"*"}}}); !errors.Is(err, ErrAlreadyDelegated) {
		t.Fatalf("takeover = %v, want ErrAlreadyDelegated", err)
	}
	if chain, err := f.svc.GetChain(ctx, bot); err != nil || chain.Root().PrincipalID != owner {
		t.Fatalf("chain after a refused takeover = %+v, %v; want rooted at the owner", chain, err)
	}
	if f.allowed(bot, "delete", "x") {
		t.Error("refused takeover widened the agent's actions")
	}

	// The delegator may change its own delegation.
	f.delegate(owner, bot, Constraints{AllowedActions: []string{"read", "write"}})
	if !f.allowed(bot, "write", "x") {
		t.Error("delegator could not replace its own delegation")
	}

	if err := f.svc.RevokeDelegation(ctx, owner, bot, "done"); err != nil {
		t.Fatalf("RevokeDelegation: %v", err)
	}
	f.delegate(intruder, bot, Constraints{})
}

// TestDelegationStaysInTheAgentsOrganization verifies that an agent of an
// organization can be delegated only by its members.
func TestDelegationStaysInTheAgentsOrganization(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	orgA, err := f.db.Organization.Create().SetName("A").SetSlug("org-a").Save(ctx)
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	orgB, err := f.db.Organization.Create().SetName("B").SetSlug("org-b").Save(ctx)
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	inOrg := func(id, org uuid.UUID) {
		t.Helper()
		if err := f.db.Principal.UpdateOneID(id).SetOrganizationID(org).Exec(ctx); err != nil {
			t.Fatalf("set organization: %v", err)
		}
	}
	member := func(id, org uuid.UUID, active bool) {
		t.Helper()
		if _, err := f.db.PrincipalMembership.Create().SetPrincipalID(id).SetOrganizationID(org).SetRole("member").SetActive(active).Save(ctx); err != nil {
			t.Fatalf("membership: %v", err)
		}
	}

	outsider := f.human(true)
	member(outsider, orgB.ID, true)
	former := f.human(true)
	member(former, orgA.ID, false)
	insider := f.human(true)
	member(insider, orgA.ID, true)
	colleague := f.agent(true)
	inOrg(colleague, orgA.ID)

	for name, delegator := range map[string]uuid.UUID{"other organization": outsider, "inactive member": former} {
		bot := f.agent(false)
		inOrg(bot, orgA.ID)
		if _, err := f.svc.CreateDelegation(ctx, CreateInput{DelegatorID: delegator, DelegateID: bot}); !errors.Is(err, ErrCrossOrganization) {
			t.Errorf("%s: %v, want ErrCrossOrganization", name, err)
		}
	}
	for name, delegator := range map[string]uuid.UUID{"member": insider, "same home organization": colleague} {
		bot := f.agent(false)
		inOrg(bot, orgA.ID)
		if _, err := f.svc.CreateDelegation(ctx, CreateInput{DelegatorID: delegator, DelegateID: bot}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
