package organization_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/approle"
	entorg "github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/resourcegrant"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/internal/pgtest"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// Every change that removes access removes it from the graph before it
// commits: when the graph refuses, the database is left unchanged, the
// error is returned whatever the sync mode, and the same call succeeds once
// the graph is back.
func TestRevocationsAbortWhenTheGraphFails(t *testing.T) {
	for _, mode := range []authz.SyncMode{authz.SyncModeStrict, authz.SyncModeEventual} {
		t.Run(string(mode), func(t *testing.T) {
			testRevocationsAbort(t, newDB(t), mode)
		})
	}
}

// The same on PostgreSQL, where the revocations also take the graph locks.
func TestRevocationsAbortWhenTheGraphFailsPostgres(t *testing.T) {
	sqlDB := pgtest.Open(t)
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sqlDB)))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	testRevocationsAbort(t, db, authz.SyncModeEventual)
}

func testRevocationsAbort(t *testing.T, db *ent.Client, mode authz.SyncMode) {
	t.Helper()
	ctx := context.Background()
	rec := syncrec.New()
	svc := organization.NewService(db, organization.WithAuthzSyncer(rec), organization.WithSyncMode(mode))
	boom := errors.New("graph down")

	owner := newHuman(t, db, "owner-"+uuid.NewString()+"@example.com")
	org, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme-" + uuid.NewString()[:8], OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatal(err)
	}
	add := func(role string) (uuid.UUID, *organization.Membership) {
		t.Helper()
		p := newHuman(t, db, role+"-"+uuid.NewString()+"@example.com")
		m, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: p, Role: role})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.AppRole.Create().
			SetPrincipalID(p).SetOrganizationID(org.ID).SetApplication("notes").SetRole("editor").
			Save(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ResourceGrant.Create().
			SetPrincipalID(p).SetOrganizationID(org.ID).SetResourceType("notes_board").SetResourceID(uuid.NewString()).SetRole("viewer").
			Save(ctx); err != nil {
			t.Fatal(err)
		}
		return p, m
	}
	membership := func(p uuid.UUID) *ent.PrincipalMembership {
		t.Helper()
		m, err := db.PrincipalMembership.Query().
			Where(principalmembership.OrganizationID(org.ID), principalmembership.PrincipalID(p)).
			Only(ctx)
		if err != nil {
			t.Fatalf("membership of %s: %v", p, err)
		}
		return m
	}
	refused := func(step string, err error) {
		t.Helper()
		if !errors.Is(err, boom) {
			t.Fatalf("%s = %v, want the graph error", step, err)
		}
	}

	// Deactivation.
	deactivated, dm := add("member")
	no := false
	rec.RemoveErr = boom
	_, err = svc.UpdateMember(ctx, dm.ID, organization.UpdateMemberInput{Active: &no})
	refused("deactivation", err)
	if !membership(deactivated).Active {
		t.Error("refused deactivation was saved")
	}

	// Role change.
	demoted, am := add("admin")
	member := "member"
	_, err = svc.UpdateMember(ctx, am.ID, organization.UpdateMemberInput{Role: &member})
	refused("demotion", err)
	if got := membership(demoted).Role; got != "admin" {
		t.Errorf("refused demotion saved role %q", got)
	}

	// Removal.
	removed, _ := add("member")
	refused("removal", svc.RemoveMember(ctx, org.ID, removed))
	membership(removed)
	if n, err := db.AppRole.Query().Where(approle.PrincipalID(removed)).Count(ctx); err != nil || n != 1 {
		t.Errorf("application roles after refused removal = %d, %v", n, err)
	}
	if n, err := db.ResourceGrant.Query().Where(resourcegrant.PrincipalID(removed)).Count(ctx); err != nil || n != 1 {
		t.Errorf("resource grants after refused removal = %d, %v", n, err)
	}

	// Ownership transfer.
	refused("transfer", svc.TransferOwnership(ctx, organization.TransferOwnershipInput{
		OrganizationID: org.ID, FromPrincipal: owner, ToPrincipal: demoted,
	}))
	if got := membership(owner).Role; got != organization.RoleOwner {
		t.Errorf("refused transfer saved the owner's role %q", got)
	}

	// Deletion.
	refused("deletion", svc.Delete(ctx, org.ID))
	if active, err := db.Organization.Query().Where(entorg.ID(org.ID), entorg.Active(true)).Exist(ctx); err != nil || !active {
		t.Errorf("refused deletion was saved: active %v, %v", active, err)
	}

	// Every call succeeds when retried, and removes what it revokes.
	rec.RemoveErr = nil
	rec.Reset()
	if _, err := svc.UpdateMember(ctx, dm.ID, organization.UpdateMemberInput{Active: &no}); err != nil {
		t.Fatalf("retried deactivation: %v", err)
	}
	if membership(deactivated).Active {
		t.Error("retried deactivation not saved")
	}
	if _, err := svc.UpdateMember(ctx, am.ID, organization.UpdateMemberInput{Role: &member}); err != nil {
		t.Fatalf("retried demotion: %v", err)
	}
	if err := svc.RemoveMember(ctx, org.ID, removed); err != nil {
		t.Fatalf("retried removal: %v", err)
	}
	if err := svc.TransferOwnership(ctx, organization.TransferOwnershipInput{
		OrganizationID: org.ID, FromPrincipal: owner, ToPrincipal: demoted,
	}); err != nil {
		t.Fatalf("retried transfer: %v", err)
	}
	if err := svc.Delete(ctx, org.ID); err != nil {
		t.Fatalf("retried deletion: %v", err)
	}
	calls := rec.Calls()
	for _, want := range []string{
		fmt.Sprintf("RemoveOrgMembership:%s:%s:member", deactivated, org.ID),
		fmt.Sprintf("RemoveAppRole:%s:%s:notes:editor", deactivated, org.ID),
		fmt.Sprintf("RemoveOrgMembership:%s:%s:admin", demoted, org.ID),
		fmt.Sprintf("AddOrgMembership:%s:%s:member", demoted, org.ID),
		fmt.Sprintf("RemoveOrgMembership:%s:%s:member", removed, org.ID),
		fmt.Sprintf("RemoveOrgMembership:%s:%s:owner", owner, org.ID),
		fmt.Sprintf("UnregisterOrganization:%s", org.ID),
		fmt.Sprintf("RemoveAppRole:%s:%s:notes:editor", demoted, org.ID),
	} {
		if !slices.Contains(calls, want) {
			t.Errorf("retries did not sync %s; calls %v", want, calls)
		}
	}
	// A revoked role leaves the graph before the role it changes to is
	// written.
	if slices.Index(calls, fmt.Sprintf("RemoveOrgMembership:%s:%s:admin", demoted, org.ID)) >
		slices.Index(calls, fmt.Sprintf("AddOrgMembership:%s:%s:member", demoted, org.ID)) {
		t.Errorf("demotion wrote the new role before removing the old one: %v", calls)
	}
}
