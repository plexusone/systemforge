package resourcegrant_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	entaccess "github.com/plexusone/systemforge/identity/ent/accesschange"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/resourcegrant"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/internal/pgtest"
	"github.com/plexusone/systemforge/internal/syncrec"

	grants "github.com/plexusone/systemforge/identity/resourcegrant"

	_ "github.com/mattn/go-sqlite3"
)

const projectType = "demo_project"

type fixture struct {
	t     *testing.T
	db    *ent.Client
	svc   *grants.Service
	orgs  organization.Service
	rec   *syncrec.Recorder
	sink  *sinkRec
	org   uuid.UUID
	actor uuid.UUID
	ctx   context.Context
	other uuid.UUID
}

type sinkRec struct {
	mu      sync.Mutex
	changes []accesschange.Change
}

func (s *sinkRec) AccessChange(c accesschange.Change) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.changes = append(s.changes, c)
}

func (s *sinkRec) reasons() []accesschange.Reason {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []accesschange.Reason
	for _, c := range s.changes {
		out = append(out, c.Reason)
	}
	return out
}

func newFixture(t *testing.T, opts ...grants.Option) *fixture {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return newFixtureOn(t, db, opts...)
}

func newFixtureOn(t *testing.T, db *ent.Client, opts ...grants.Option) *fixture {
	t.Helper()
	f := &fixture{t: t, db: db, rec: syncrec.New(), sink: &sinkRec{}, ctx: context.Background()}
	f.svc = grants.NewService(db, append([]grants.Option{
		grants.WithAuthzSyncer(f.rec, authz.SyncModeStrict),
		grants.WithAccessChangeSink(f.sink),
	}, opts...)...)
	f.orgs = organization.NewService(db)
	f.actor = f.principal()
	f.org = f.newOrg(f.actor)
	f.other = f.newOrg(f.actor)
	return f
}

func (f *fixture) principal() uuid.UUID {
	f.t.Helper()
	p, err := f.db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("P").Save(f.ctx)
	if err != nil {
		f.t.Fatalf("principal: %v", err)
	}
	return p.ID
}

func (f *fixture) newOrg(owner uuid.UUID) uuid.UUID {
	f.t.Helper()
	org, err := f.orgs.Create(f.ctx, organization.CreateOrganizationInput{
		Name: "Org", Slug: "org-" + uuid.NewString()[:8], OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner,
	})
	if err != nil {
		f.t.Fatalf("organization: %v", err)
	}
	return org.ID
}

func (f *fixture) ref(org uuid.UUID) authz.ResourceRef {
	return authz.ResourceRef{Type: projectType, ID: uuid.NewString(), OrganizationID: org}
}

func (f *fixture) role(who, org uuid.UUID) string {
	f.t.Helper()
	m, err := f.db.PrincipalMembership.Query().
		Where(principalmembership.PrincipalID(who), principalmembership.OrganizationID(org)).
		Only(f.ctx)
	if ent.IsNotFound(err) {
		return ""
	}
	if err != nil {
		f.t.Fatalf("membership: %v", err)
	}
	if !m.Active {
		return "inactive:" + m.Role
	}
	return m.Role
}

// recordedReasons returns the reasons of the sf_access_changes rows of one
// principal in the organization, oldest first.
func (f *fixture) recordedReasons(who, org uuid.UUID) []string {
	f.t.Helper()
	rows, err := f.db.AccessChange.Query().
		Where(entaccess.PrincipalID(who), entaccess.OrganizationID(org)).
		Order(ent.Asc(entaccess.FieldChangedAt), ent.Asc(entaccess.FieldID)).
		All(f.ctx)
	if err != nil {
		f.t.Fatalf("access changes: %v", err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.Reason)
	}
	return out
}

func (f *fixture) grant(who uuid.UUID, ref authz.ResourceRef, role string) {
	f.t.Helper()
	if err := f.svc.GrantResourceRole(f.ctx, who, ref, role, f.actor); err != nil {
		f.t.Fatalf("GrantResourceRole(%s): %v", role, err)
	}
}

// TestFirstGrantCreatesCollaboratorAndLastRevokeRemovesIt covers the
// membership lifecycle and the access changes each step records.
func TestFirstGrantCreatesCollaboratorAndLastRevokeRemovesIt(t *testing.T) {
	f := newFixture(t)
	who := f.principal()
	first, second := f.ref(f.org), f.ref(f.org)

	f.grant(who, first, authz.ResourceRoleViewer)
	if got := f.role(who, f.org); got != "collaborator" {
		t.Fatalf("role after the first grant = %q, want collaborator", got)
	}
	// Granting access records nothing: tokens issued earlier stay valid.
	if got := f.recordedReasons(who, f.org); len(got) != 0 {
		t.Errorf("access changes after a first grant = %v, want none", got)
	}
	wantCalls := []string{
		fmt.Sprintf("AddOrgMembership:%s:%s:collaborator", who, f.org),
		fmt.Sprintf("SetResourceGrant:%s:%s:%s:%s:viewer", who, f.org, first.Type, first.ID),
	}
	if got := f.rec.Calls(); !slices.Equal(got, wantCalls) {
		t.Errorf("syncer calls = %v, want %v", got, wantCalls)
	}

	// A second grant does not add the membership again.
	f.grant(who, second, authz.ResourceRoleMaintainer)
	if got := f.rec.Calls(); len(got) != 3 || got[2] != fmt.Sprintf("SetResourceGrant:%s:%s:%s:%s:maintainer", who, f.org, second.Type, second.ID) {
		t.Errorf("syncer calls after the second grant = %v", got)
	}

	// Raising a role records nothing; lowering one records grant_reduced.
	f.grant(who, first, authz.ResourceRoleContributor)
	if got := f.recordedReasons(who, f.org); len(got) != 0 {
		t.Errorf("access changes after raising a role = %v, want none", got)
	}
	f.grant(who, second, authz.ResourceRoleViewer)
	if got := f.recordedReasons(who, f.org); !slices.Equal(got, []string{"grant_reduced"}) {
		t.Errorf("access changes after lowering a role = %v, want [grant_reduced]", got)
	}
	// Regranting the same role changes nothing.
	f.grant(who, second, authz.ResourceRoleViewer)
	if got := f.recordedReasons(who, f.org); len(got) != 1 {
		t.Errorf("access changes after a no-op grant = %v", got)
	}

	// Revoking a grant records grant_reduced and keeps the membership.
	if err := f.svc.RevokeResourceRole(f.ctx, who, first); err != nil {
		t.Fatalf("RevokeResourceRole: %v", err)
	}
	if got := f.role(who, f.org); got != "collaborator" {
		t.Errorf("role with a grant left = %q", got)
	}
	if got := f.recordedReasons(who, f.org); !slices.Equal(got, []string{"grant_reduced", "grant_reduced"}) {
		t.Errorf("access changes after a revoke = %v", got)
	}

	// Revoking the last one also removes the membership.
	if err := f.svc.RevokeResourceRole(f.ctx, who, second); err != nil {
		t.Fatalf("RevokeResourceRole: %v", err)
	}
	if got := f.role(who, f.org); got != "" {
		t.Errorf("role after the last revoke = %q, want none", got)
	}
	if got := f.recordedReasons(who, f.org); !slices.Equal(got, []string{"grant_reduced", "grant_reduced", "grant_reduced", "membership_removed"}) {
		t.Errorf("access changes after the last revoke = %v", got)
	}
	tail := f.rec.Calls()[len(f.rec.Calls())-2:]
	wantTail := []string{
		fmt.Sprintf("RemoveResourceGrant:%s:%s:%s:%s", who, f.org, second.Type, second.ID),
		fmt.Sprintf("RemoveOrgMembership:%s:%s:collaborator", who, f.org),
	}
	if !slices.Equal(tail, wantTail) {
		t.Errorf("syncer calls after the last revoke = %v, want %v", tail, wantTail)
	}
	// The sink saw what was recorded, after commit.
	if got := f.sink.reasons(); !slices.Equal(got, []accesschange.Reason{
		accesschange.GrantReduced, accesschange.GrantReduced, accesschange.GrantReduced, accesschange.MembershipRemoved,
	}) {
		t.Errorf("sink saw %v", got)
	}
}

// TestRevokeKeepsMembersAndOtherOrganizations checks that a member who is
// granted and revoked stays a member, and that a collaborator's grants in
// one organization do not keep their membership in another.
func TestRevokeKeepsMembersAndOtherOrganizations(t *testing.T) {
	f := newFixture(t)
	member := f.principal()
	if _, err := f.orgs.AddMember(f.ctx, organization.AddMemberInput{OrganizationID: f.org, PrincipalID: member, Role: "member"}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	ref := f.ref(f.org)
	f.grant(member, ref, authz.ResourceRoleMaintainer)
	if err := f.svc.RevokeResourceRole(f.ctx, member, ref); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := f.role(member, f.org); got != "member" {
		t.Errorf("a member's role after grant and revoke = %q, want member", got)
	}

	// A collaborator in two organizations.
	who := f.principal()
	a, b := f.ref(f.org), f.ref(f.other)
	f.grant(who, a, authz.ResourceRoleViewer)
	f.grant(who, b, authz.ResourceRoleViewer)
	if err := f.svc.RevokeResourceRole(f.ctx, who, a); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if f.role(who, f.org) != "" || f.role(who, f.other) != "collaborator" {
		t.Errorf("roles after revoking in one organization = %q, %q", f.role(who, f.org), f.role(who, f.other))
	}
}

// TestRemoveMemberDeletesGrants checks that removing a member from the
// organization takes their grants with it, so access does not outlive the
// membership, and that the graph is told.
func TestRemoveMemberDeletesGrants(t *testing.T) {
	f := newFixture(t)
	orgSvc := organization.NewService(f.db, organization.WithAuthzSyncer(f.rec))
	who := f.principal()
	ref := f.ref(f.org)
	f.grant(who, ref, authz.ResourceRoleContributor)
	before := len(f.rec.Calls())

	if err := orgSvc.RemoveMember(f.ctx, f.org, who); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	n, err := f.db.ResourceGrant.Query().Where(resourcegrant.PrincipalID(who)).Count(f.ctx)
	if err != nil || n != 0 {
		t.Errorf("grants after RemoveMember = %d, %v; want 0", n, err)
	}
	role, err := f.svc.ResourceRole(f.ctx, who, ref)
	if err != nil || role != "" {
		t.Errorf("ResourceRole after RemoveMember = %q, %v", role, err)
	}
	calls := f.rec.Calls()[before:]
	want := fmt.Sprintf("RemoveResourceGrant:%s:%s:%s:%s", who, f.org, ref.Type, ref.ID)
	if !slices.Contains(calls, want) {
		t.Errorf("syncer calls %v lack %s", calls, want)
	}
}

// TestInactiveMembership checks that grants do not apply while the
// membership is inactive, that a collaborator is reactivated by a grant,
// and that another role's inactive membership is refused.
func TestInactiveMembership(t *testing.T) {
	f := newFixture(t)
	who := f.principal()
	ref := f.ref(f.org)
	f.grant(who, ref, authz.ResourceRoleViewer)

	m, err := f.orgs.GetMembership(f.ctx, f.org, who)
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	inactive := false
	if _, err := f.orgs.UpdateMember(f.ctx, m.ID, organization.UpdateMemberInput{Active: &inactive}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if role, err := f.svc.ResourceRole(f.ctx, who, ref); err != nil || role != "" {
		t.Errorf("ResourceRole for an inactive membership = %q, %v", role, err)
	}
	if set, err := f.svc.ListResources(f.ctx, who, projectType, authz.PermResourceView); err != nil || len(set.IDs) != 0 {
		t.Errorf("ListResources for an inactive membership = %+v, %v", set, err)
	}
	// A grant reactivates a deactivated collaborator.
	f.grant(who, f.ref(f.org), authz.ResourceRoleViewer)
	if got := f.role(who, f.org); got != "collaborator" {
		t.Errorf("role after regranting = %q", got)
	}

	// A deactivated member stays so until an administrator acts.
	member := f.principal()
	mm, err := f.orgs.AddMember(f.ctx, organization.AddMemberInput{OrganizationID: f.org, PrincipalID: member, Role: "member"})
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if _, err := f.orgs.UpdateMember(f.ctx, mm.ID, organization.UpdateMemberInput{Active: &inactive}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	err = f.svc.GrantResourceRole(f.ctx, member, f.ref(f.org), authz.ResourceRoleViewer, uuid.Nil)
	if !errors.Is(err, grants.ErrInactiveMembership) {
		t.Errorf("granting to a deactivated member = %v, want ErrInactiveMembership", err)
	}
}

// TestSyncModes checks that a sync failure is returned in strict mode and
// logged in eventual mode, with the rows stored either way.
func TestSyncModes(t *testing.T) {
	f := newFixture(t) // strict
	f.rec.Err = errors.New("graph down")
	who := f.principal()
	ref := f.ref(f.org)
	if err := f.svc.GrantResourceRole(f.ctx, who, ref, authz.ResourceRoleViewer, uuid.Nil); err == nil {
		t.Error("strict mode swallowed a sync failure")
	}
	if role, err := f.svc.ResourceRole(f.ctx, who, ref); err != nil || role != authz.ResourceRoleViewer {
		t.Errorf("the grant was not stored: %q, %v", role, err)
	}

	failing := syncrec.New()
	failing.Err = errors.New("graph down")
	e := newFixture(t, grants.WithAuthzSyncer(failing, authz.SyncModeEventual))
	if err := e.svc.GrantResourceRole(e.ctx, e.principal(), e.ref(e.org), authz.ResourceRoleViewer, uuid.Nil); err != nil {
		t.Errorf("eventual mode returned a sync failure: %v", err)
	}
}

// TestValidation covers the refusals of the service.
func TestValidation(t *testing.T) {
	registry := authz.NewVocabularyRegistry()
	f := newFixture(t, grants.WithVocabularies(registry))
	who := f.principal()
	if err := f.svc.GrantResourceRole(f.ctx, who, f.ref(f.org), authz.ResourceRoleViewer, uuid.Nil); !errors.Is(err, authz.ErrInvalidResource) {
		t.Errorf("unregistered application = %v, want ErrInvalidResource", err)
	}
	if err := f.svc.GrantResourceRole(f.ctx, who, f.ref(f.org), "editor", uuid.Nil); !errors.Is(err, authz.ErrInvalidResourceRole) {
		t.Errorf("editor = %v, want ErrInvalidResourceRole", err)
	}
	// An unknown principal is refused by the database, and leaves nothing.
	if err := f.svc.GrantResourceRole(f.ctx, uuid.New(), f.ref(f.org), authz.ResourceRoleViewer, uuid.Nil); err == nil {
		t.Error("granting to an unknown principal succeeded")
	}
	if n, err := f.db.ResourceGrant.Query().Count(f.ctx); err != nil || n != 0 {
		t.Errorf("grants stored = %d, %v", n, err)
	}
}

// TestConcurrentGrantsAndRevokes grants one new principal many resources at
// once and then revokes them at once, on PostgreSQL: exactly one
// collaborator membership results, and it is gone after the last revoke.
func TestConcurrentGrantsAndRevokes(t *testing.T) {
	sqlDB := pgtest.Open(t)
	sqlDB.SetMaxOpenConns(30)
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sqlDB)))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	f := newFixtureOn(t, db)
	f.svc = grants.NewService(db) // no syncer: the recorder is not for concurrent use
	who := f.principal()
	const n = 12
	refs := make([]authz.ResourceRef, n)
	for i := range refs {
		refs[i] = f.ref(f.org)
	}
	run := func(fn func(i int) error) {
		t.Helper()
		var wg sync.WaitGroup
		errs := make([]error, n)
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = fn(i)
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("call %d: %v", i, err)
			}
		}
	}
	run(func(i int) error {
		return f.svc.GrantResourceRole(f.ctx, who, refs[i], authz.ResourceRoleViewer, uuid.Nil)
	})
	count, err := db.PrincipalMembership.Query().Where(principalmembership.PrincipalID(who), principalmembership.OrganizationID(f.org)).Count(f.ctx)
	if err != nil || count != 1 {
		t.Fatalf("memberships = %d, %v; want 1", count, err)
	}
	run(func(i int) error { return f.svc.RevokeResourceRole(f.ctx, who, refs[i]) })
	if got := f.role(who, f.org); got != "" {
		t.Errorf("role after revoking everything concurrently = %q, want none", got)
	}
}

// TestRevocationAbortsWhenTheGraphFails checks that a revocation, and a
// grant lowered to a lesser role, change the graph before they commit: the
// graph's refusal leaves the rows as they were, whatever the sync mode,
// and the same call succeeds when retried.
func TestRevocationAbortsWhenTheGraphFails(t *testing.T) {
	for _, mode := range []authz.SyncMode{authz.SyncModeStrict, authz.SyncModeEventual} {
		t.Run(string(mode), func(t *testing.T) {
			rec := syncrec.New()
			f := newFixture(t, grants.WithAuthzSyncer(rec, mode))
			boom := errors.New("graph down")
			who := f.principal()
			ref := f.ref(f.org)
			if err := f.svc.GrantResourceRole(f.ctx, who, ref, authz.ResourceRoleMaintainer, uuid.Nil); err != nil {
				t.Fatal(err)
			}

			rec.Err = boom
			if err := f.svc.GrantResourceRole(f.ctx, who, ref, authz.ResourceRoleViewer, uuid.Nil); !errors.Is(err, boom) {
				t.Errorf("lowering = %v, want the graph error", err)
			}
			if role, err := f.svc.ResourceRole(f.ctx, who, ref); err != nil || role != authz.ResourceRoleMaintainer {
				t.Errorf("role after refused lowering = %q, %v", role, err)
			}
			if err := f.svc.RevokeResourceRole(f.ctx, who, ref); !errors.Is(err, boom) {
				t.Errorf("revoke = %v, want the graph error", err)
			}
			if role, err := f.svc.ResourceRole(f.ctx, who, ref); err != nil || role != authz.ResourceRoleMaintainer {
				t.Errorf("role after refused revoke = %q, %v", role, err)
			}
			if got := f.role(who, f.org); got != "collaborator" {
				t.Errorf("membership after refused revoke = %q", got)
			}

			rec.Err = nil
			rec.Reset()
			if err := f.svc.GrantResourceRole(f.ctx, who, ref, authz.ResourceRoleViewer, uuid.Nil); err != nil {
				t.Fatalf("retried lowering: %v", err)
			}
			if err := f.svc.RevokeResourceRole(f.ctx, who, ref); err != nil {
				t.Fatalf("retried revoke: %v", err)
			}
			if got := f.role(who, f.org); got != "" {
				t.Errorf("membership after revoke = %q, want none", got)
			}
			want := []string{
				fmt.Sprintf("SetResourceGrant:%s:%s:%s:%s:viewer", who, f.org, ref.Type, ref.ID),
				fmt.Sprintf("RemoveResourceGrant:%s:%s:%s:%s", who, f.org, ref.Type, ref.ID),
				fmt.Sprintf("RemoveOrgMembership:%s:%s:collaborator", who, f.org),
			}
			if got := rec.Calls(); !slices.Equal(got, want) {
				t.Errorf("calls = %v, want %v", got, want)
			}
		})
	}
}
