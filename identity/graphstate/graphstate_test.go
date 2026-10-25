package graphstate_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/graphstate"

	_ "github.com/mattn/go-sqlite3"
)

type fixture struct {
	t   *testing.T
	ctx context.Context
	db  *ent.Client
}

func newFixture(t *testing.T) *fixture {
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return &fixture{t: t, ctx: context.Background(), db: db}
}

func (f *fixture) person(admin bool) uuid.UUID {
	f.t.Helper()
	p, err := f.db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("P").Save(f.ctx)
	if err != nil {
		f.t.Fatalf("principal: %v", err)
	}
	if _, err := f.db.Human.Create().SetPrincipalID(p.ID).SetEmail(p.Identifier).SetIsPlatformAdmin(admin).Save(f.ctx); err != nil {
		f.t.Fatalf("human: %v", err)
	}
	return p.ID
}

func (f *fixture) org(active bool) uuid.UUID {
	f.t.Helper()
	o, err := f.db.Organization.Create().SetName("Org").SetSlug("org-" + uuid.NewString()[:8]).SetActive(active).Save(f.ctx)
	if err != nil {
		f.t.Fatalf("organization: %v", err)
	}
	return o.ID
}

func (f *fixture) member(o, p uuid.UUID, role string, active bool) {
	f.t.Helper()
	if _, err := f.db.PrincipalMembership.Create().SetOrganizationID(o).SetPrincipalID(p).SetRole(role).SetActive(active).Save(f.ctx); err != nil {
		f.t.Fatalf("membership: %v", err)
	}
}

func (f *fixture) deactivate(p uuid.UUID) {
	f.t.Helper()
	if _, err := f.db.Principal.UpdateOneID(p).SetActive(false).Save(f.ctx); err != nil {
		f.t.Fatalf("deactivate: %v", err)
	}
}

func (f *fixture) want(name string, got bool, err error, want bool) {
	f.t.Helper()
	if err != nil {
		f.t.Fatalf("%s: %v", name, err)
	}
	if got != want {
		f.t.Errorf("%s = %v, want %v", name, got, want)
	}
}

func TestMembership(t *testing.T) {
	f := newFixture(t)
	org, gone := f.org(true), f.org(false)
	member, paused, off := f.person(false), f.person(false), f.person(false)
	f.member(org, member, "member", true)
	f.member(gone, member, "member", true)
	f.member(org, paused, "member", false)
	f.member(org, off, "admin", true)
	f.deactivate(off)

	got, err := graphstate.Membership(f.ctx, f.db, org, member, "member")
	f.want("active member", got, err, true)
	got, err = graphstate.Membership(f.ctx, f.db, org, member)
	f.want("active member, any role", got, err, true)
	got, err = graphstate.Membership(f.ctx, f.db, org, member, "admin")
	f.want("active member as admin", got, err, false)
	got, err = graphstate.Membership(f.ctx, f.db, gone, member)
	f.want("member of a deleted organization", got, err, false)
	got, err = graphstate.Membership(f.ctx, f.db, org, paused)
	f.want("deactivated membership", got, err, false)
	got, err = graphstate.Membership(f.ctx, f.db, org, off, "admin")
	f.want("deactivated principal", got, err, false)
}

func TestAppRole(t *testing.T) {
	f := newFixture(t)
	org := f.org(true)
	member, collab, off := f.person(false), f.person(false), f.person(false)
	f.member(org, member, "member", true)
	f.member(org, collab, "collaborator", true)
	f.member(org, off, "member", true)
	f.deactivate(off)
	for _, p := range []uuid.UUID{member, collab, off} {
		if _, err := f.db.AppRole.Create().SetOrganizationID(org).SetPrincipalID(p).SetApplication("demo").SetRole("editor").Save(f.ctx); err != nil {
			t.Fatalf("app role: %v", err)
		}
	}

	got, err := graphstate.AppRole(f.ctx, f.db, org, member, "demo", "editor")
	f.want("member's role", got, err, true)
	got, err = graphstate.AppRole(f.ctx, f.db, org, member, "demo", "admin")
	f.want("a role not held", got, err, false)
	got, err = graphstate.AppRole(f.ctx, f.db, org, collab, "demo", "editor")
	f.want("collaborator's role", got, err, false)
	got, err = graphstate.AppRole(f.ctx, f.db, org, off, "demo", "editor")
	f.want("deactivated principal's role", got, err, false)
}

func TestResourceGrant(t *testing.T) {
	f := newFixture(t)
	org, other := f.org(true), f.org(true)
	collab, off := f.person(false), f.person(false)
	f.member(org, collab, "collaborator", true)
	f.member(org, off, "collaborator", true)
	f.deactivate(off)
	for _, p := range []uuid.UUID{collab, off} {
		if _, err := f.db.ResourceGrant.Create().SetOrganizationID(org).SetPrincipalID(p).SetResourceType("demo_doc").SetResourceID("d1").SetRole("viewer").Save(f.ctx); err != nil {
			t.Fatalf("grant: %v", err)
		}
	}

	got, err := graphstate.ResourceGrant(f.ctx, f.db, org, collab, "demo_doc", "d1", "viewer")
	f.want("collaborator's grant", got, err, true)
	got, err = graphstate.ResourceGrant(f.ctx, f.db, org, collab, "demo_doc", "d1", "maintainer")
	f.want("a higher role", got, err, false)
	got, err = graphstate.ResourceGrant(f.ctx, f.db, other, collab, "demo_doc", "d1", "viewer")
	f.want("another organization", got, err, false)
	got, err = graphstate.ResourceGrant(f.ctx, f.db, org, off, "demo_doc", "d1", "viewer")
	f.want("deactivated principal's grant", got, err, false)
}

func TestPlatformAdminAndManager(t *testing.T) {
	f := newFixture(t)
	admin, off, plain, child := f.person(true), f.person(true), f.person(false), f.person(false)
	f.deactivate(off)
	if _, err := f.db.ManagerRelationship.Create().SetManagedPrincipalID(child).SetManagerPrincipalID(admin).SetRole("guardian").Save(f.ctx); err != nil {
		t.Fatalf("manager: %v", err)
	}
	if _, err := f.db.ManagerRelationship.Create().SetManagedPrincipalID(child).SetManagerPrincipalID(off).SetRole("guardian").Save(f.ctx); err != nil {
		t.Fatalf("manager: %v", err)
	}
	if _, err := f.db.ManagerRelationship.Create().SetManagedPrincipalID(child).SetManagerPrincipalID(plain).SetRole("educator").SetActive(false).Save(f.ctx); err != nil {
		t.Fatalf("manager: %v", err)
	}

	got, err := graphstate.PlatformAdmin(f.ctx, f.db, admin)
	f.want("platform administrator", got, err, true)
	got, err = graphstate.PlatformAdmin(f.ctx, f.db, off)
	f.want("deactivated platform administrator", got, err, false)
	got, err = graphstate.PlatformAdmin(f.ctx, f.db, plain)
	f.want("not an administrator", got, err, false)

	got, err = graphstate.Manager(f.ctx, f.db, child, admin, "guardian")
	f.want("active guardian", got, err, true)
	got, err = graphstate.Manager(f.ctx, f.db, child, off, "guardian")
	f.want("deactivated guardian", got, err, false)
	got, err = graphstate.Manager(f.ctx, f.db, child, plain, "educator")
	f.want("ended relationship", got, err, false)
}

func TestCanHoldAppRoles(t *testing.T) {
	for role, want := range map[string]bool{"owner": true, "admin": true, "member": true, "collaborator": false, "": false} {
		if got := graphstate.CanHoldAppRoles(role); got != want {
			t.Errorf("CanHoldAppRoles(%q) = %v, want %v", role, got, want)
		}
	}
}
