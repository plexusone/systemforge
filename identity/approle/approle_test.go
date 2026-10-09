package approle_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// ladderVocab declares the standard application role ladder.
type ladderVocab struct{ app string }

func (v ladderVocab) App() string { return v.app }
func (ladderVocab) Roles() authz.RolePermissions {
	return authz.RolePermissions{
		"viewer":      {"item.read"},
		"contributor": {"item.read", "item.write"},
		"maintainer":  {"item.read", "item.write", "item.manage"},
		"admin":       {"item.read", "item.write", "item.manage", "app.admin"},
	}
}
func (ladderVocab) Hierarchy() authz.RoleHierarchy {
	return authz.RoleHierarchy{"viewer": 10, "contributor": 20, "maintainer": 30, "admin": 40}
}
func (v ladderVocab) Scopes() []string    { return []string{v.app + ":admin"} }
func (ladderVocab) SpiceDBSchema() string { return "" }

type fixture struct {
	t      *testing.T
	db     *ent.Client
	orgs   organization.Service
	svc    *approle.Service
	org    *organization.Organization
	owner  uuid.UUID
	admin  uuid.UUID
	member uuid.UUID
}

func newFixture(t *testing.T, opts ...approle.Option) *fixture {
	t.Helper()
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	reg := authz.NewVocabularyRegistry()
	for _, app := range []string{"alpha", "beta"} {
		if err := reg.Register(ladderVocab{app: app}); err != nil {
			t.Fatalf("register %s: %v", app, err)
		}
	}
	if len(opts) == 0 {
		opts = []approle.Option{approle.EntitleAll(reg)}
	}
	f := &fixture{t: t, db: db, orgs: organization.NewService(db), svc: approle.NewService(db, reg, opts...)}
	f.owner = f.human("owner@example.com")
	f.admin = f.human("admin@example.com")
	f.member = f.human("member@example.com")
	org, err := f.orgs.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &f.owner})
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	f.org = org
	f.addMember(f.admin, organization.RoleAdmin)
	f.addMember(f.member, organization.RoleMember)
	return f
}

func (f *fixture) human(email string) uuid.UUID {
	f.t.Helper()
	p, err := f.db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier(email).SetDisplayName(email).Save(context.Background())
	if err != nil {
		f.t.Fatalf("create principal: %v", err)
	}
	return p.ID
}

func (f *fixture) addMember(id uuid.UUID, role string) {
	f.t.Helper()
	if _, err := f.orgs.AddMember(context.Background(), organization.AddMemberInput{OrganizationID: f.org.ID, PrincipalID: id, Role: role}); err != nil {
		f.t.Fatalf("add %s: %v", role, err)
	}
}

func (f *fixture) in(principalID uuid.UUID, app, role string) approle.AssignInput {
	return approle.AssignInput{OrganizationID: f.org.ID, PrincipalID: principalID, Application: app, Role: role, AssignedBy: f.admin}
}

func TestNoRolesByDefault(t *testing.T) {
	f := newFixture(t)
	for name, id := range map[string]uuid.UUID{"admin": f.admin, "member": f.member} {
		got, err := f.svc.EffectiveRoles(context.Background(), id, f.org.ID)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != 0 {
			t.Errorf("%s effective roles = %v, want none", name, got)
		}
	}
}

func TestOwnerHoldsAdminImplicitly(t *testing.T) {
	f := newFixture(t)
	got, err := f.svc.EffectiveRoles(context.Background(), f.owner, f.org.ID)
	if err != nil {
		t.Fatalf("EffectiveRoles: %v", err)
	}
	if len(got) != 2 || got["alpha"] != "admin" || got["beta"] != "admin" {
		t.Errorf("owner roles = %v, want admin in alpha and beta", got)
	}
	stored, err := f.svc.ListForPrincipal(context.Background(), f.org.ID, f.owner)
	if err != nil || len(stored) != 0 {
		t.Errorf("owner stored roles = %v, %v; want none", stored, err)
	}
}

func TestAdminHoldsOnlyWhatIsAssigned(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	// An admin may assign roles to themselves.
	if _, err := f.svc.Assign(ctx, f.in(f.admin, "alpha", "maintainer")); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	got, err := f.svc.EffectiveRoles(ctx, f.admin, f.org.ID)
	if err != nil {
		t.Fatalf("EffectiveRoles: %v", err)
	}
	if len(got) != 1 || got["alpha"] != "maintainer" {
		t.Errorf("admin roles = %v, want maintainer in alpha only", got)
	}
}

func TestAssignChangeRemove(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if _, err := f.svc.Assign(ctx, f.in(f.member, "alpha", "viewer")); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if _, err := f.svc.Assign(ctx, f.in(f.member, "alpha", "admin")); !errors.Is(err, approle.ErrAlreadyAssigned) {
		t.Errorf("second Assign = %v, want ErrAlreadyAssigned", err)
	}
	r, err := f.svc.Change(ctx, f.in(f.member, "alpha", "contributor"))
	if err != nil || r.Role != "contributor" {
		t.Fatalf("Change = %+v, %v", r, err)
	}
	if _, err := f.svc.Change(ctx, f.in(f.member, "beta", "viewer")); !errors.Is(err, approle.ErrNotAssigned) {
		t.Errorf("Change of unassigned = %v, want ErrNotAssigned", err)
	}
	list, err := f.svc.ListForOrganization(ctx, f.org.ID, "alpha")
	if err != nil || len(list) != 1 || list[0].Role != "contributor" || list[0].AssignedBy == nil || *list[0].AssignedBy != f.admin {
		t.Errorf("ListForOrganization = %+v, %v", list, err)
	}
	if err := f.svc.Remove(ctx, f.org.ID, f.member, "alpha", f.admin); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := f.svc.Remove(ctx, f.org.ID, f.member, "alpha", f.admin); !errors.Is(err, approle.ErrNotAssigned) {
		t.Errorf("second Remove = %v, want ErrNotAssigned", err)
	}
}

func TestAssignValidation(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	outsider := f.human("outsider@example.com")
	collab := f.human("collab@example.com")
	f.addMember(collab, "collaborator")
	inactive := f.human("inactive@example.com")
	f.addMember(inactive, organization.RoleMember)
	m, err := f.orgs.GetMembership(ctx, f.org.ID, inactive)
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	off := false
	if _, err := f.orgs.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Active: &off}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}

	tests := []struct {
		name string
		in   approle.AssignInput
		want error
	}{
		{"unknown application", f.in(f.member, "nope", "viewer"), approle.ErrUnknownApplication},
		{"role outside the vocabulary", f.in(f.member, "alpha", "superuser"), approle.ErrUnknownRole},
		{"non-member", f.in(outsider, "alpha", "viewer"), approle.ErrNotMember},
		{"collaborator", f.in(collab, "alpha", "viewer"), approle.ErrNotMember},
		{"inactive member", f.in(inactive, "alpha", "viewer"), approle.ErrNotMember},
	}
	for _, tc := range tests {
		if _, err := f.svc.Assign(ctx, tc.in); !errors.Is(err, tc.want) {
			t.Errorf("%s: Assign = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestEntitlementsLimitRoles(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, approle.WithEntitlements(func(_ context.Context, _ uuid.UUID, app string) (bool, error) {
		return app == "alpha", nil
	}))
	if _, err := f.svc.Assign(ctx, f.in(f.member, "beta", "viewer")); !errors.Is(err, approle.ErrNotEntitled) {
		t.Errorf("Assign in unentitled app = %v, want ErrNotEntitled", err)
	}
	got, err := f.svc.EffectiveRoles(ctx, f.owner, f.org.ID)
	if err != nil || len(got) != 1 || got["alpha"] != "admin" {
		t.Errorf("owner roles = %v, %v; want admin in alpha only", got, err)
	}
}

func TestRemovingMemberDeletesRoles(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	for _, app := range []string{"alpha", "beta"} {
		if _, err := f.svc.Assign(ctx, f.in(f.member, app, "viewer")); err != nil {
			t.Fatalf("Assign: %v", err)
		}
	}
	if _, err := f.svc.Assign(ctx, f.in(f.admin, "alpha", "viewer")); err != nil {
		t.Fatalf("Assign admin: %v", err)
	}
	if err := f.orgs.RemoveMember(ctx, f.org.ID, f.member); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if list, err := f.svc.ListForPrincipal(ctx, f.org.ID, f.member); err != nil || len(list) != 0 {
		t.Errorf("roles after removal = %v, %v; want none", list, err)
	}
	if list, err := f.svc.ListForPrincipal(ctx, f.org.ID, f.admin); err != nil || len(list) != 1 {
		t.Errorf("other member's roles = %v, %v; want one", list, err)
	}
	// Re-adding the person brings back nothing.
	f.addMember(f.member, organization.RoleMember)
	got, err := f.svc.EffectiveRoles(ctx, f.member, f.org.ID)
	if err != nil || len(got) != 0 {
		t.Errorf("roles after re-adding = %v, %v; want none", got, err)
	}
}

func TestDeactivatedMemberHoldsNoRoles(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if _, err := f.svc.Assign(ctx, f.in(f.member, "alpha", "viewer")); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	m, err := f.orgs.GetMembership(ctx, f.org.ID, f.member)
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	off := false
	if _, err := f.orgs.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Active: &off}); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	got, err := f.svc.EffectiveRoles(ctx, f.member, f.org.ID)
	if err != nil || len(got) != 0 {
		t.Errorf("roles while deactivated = %v, %v; want none", got, err)
	}
}

func TestRolesLowestFirst(t *testing.T) {
	f := newFixture(t)
	got, err := f.svc.Roles("alpha")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	want := []string{"viewer", "contributor", "maintainer", "admin"}
	if len(got) != len(want) {
		t.Fatalf("Roles = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Roles = %v, want %v", got, want)
		}
	}
}

func TestNoEntitlementSourceMeansNoEntitlements(t *testing.T) {
	ctx := context.Background()
	reg := authz.NewVocabularyRegistry()
	if err := reg.Register(ladderVocab{app: "alpha"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// newFixture would add EntitleAll for no options, so build by hand.
	f := newFixture(t)
	svc := approle.NewService(f.db, reg)
	if _, err := svc.Assign(ctx, f.in(f.member, "alpha", "viewer")); !errors.Is(err, approle.ErrNotEntitled) {
		t.Errorf("Assign without a source = %v, want ErrNotEntitled", err)
	}
	got, err := svc.EffectiveRoles(ctx, f.owner, f.org.ID)
	if err != nil || len(got) != 0 {
		t.Errorf("owner roles without a source = %v, %v; want none", got, err)
	}
}

func TestSeatLimit(t *testing.T) {
	ctx := context.Background()
	one := 1
	f := newFixture(t, approle.WithEntitlementGrants(func(context.Context, uuid.UUID) (map[string]approle.Grant, error) {
		return map[string]approle.Grant{"alpha": {SeatLimit: &one}, "beta": {}}, nil
	}))
	if _, err := f.svc.Assign(ctx, f.in(f.member, "alpha", "viewer")); err != nil {
		t.Fatalf("first seat: %v", err)
	}
	if _, err := f.svc.Assign(ctx, f.in(f.admin, "alpha", "viewer")); !errors.Is(err, approle.ErrNoSeats) {
		t.Errorf("second seat = %v, want ErrNoSeats", err)
	}
	if _, err := f.svc.Assign(ctx, f.in(f.member, "alpha", "viewer")); !errors.Is(err, approle.ErrAlreadyAssigned) {
		t.Errorf("reassign at the limit = %v, want ErrAlreadyAssigned", err)
	}
	if _, err := f.svc.Change(ctx, f.in(f.member, "alpha", "admin")); err != nil {
		t.Errorf("change at the limit: %v", err)
	}
	if _, err := f.svc.Assign(ctx, f.in(f.admin, "beta", "viewer")); err != nil {
		t.Errorf("unlimited application: %v", err)
	}
	// Owners hold their implicit role without a seat.
	got, err := f.svc.EffectiveRoles(ctx, f.owner, f.org.ID)
	if err != nil || got["alpha"] != "admin" {
		t.Errorf("owner roles = %v, %v", got, err)
	}
	if err := f.svc.Remove(ctx, f.org.ID, f.member, "alpha", f.owner); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := f.svc.Assign(ctx, f.in(f.admin, "alpha", "viewer")); err != nil {
		t.Errorf("seat freed by Remove: %v", err)
	}
}

// syncedFixture returns a fixture whose service writes to a recording
// syncer.
func syncedFixture(t *testing.T, mode authz.SyncMode) (*fixture, *syncrec.Recorder) {
	t.Helper()
	rec := syncrec.New()
	f := newFixture(t)
	reg := authz.NewVocabularyRegistry()
	for _, app := range []string{"alpha", "beta"} {
		if err := reg.Register(ladderVocab{app: app}); err != nil {
			t.Fatal(err)
		}
	}
	f.svc = approle.NewService(f.db, reg, approle.EntitleAll(reg), approle.WithAuthzSyncer(rec, mode))
	return f, rec
}

func appCalls(rec *syncrec.Recorder) []string {
	var out []string
	for _, c := range rec.Calls() {
		if strings.Contains(c, "AppRole") {
			out = append(out, c)
		}
	}
	return out
}

func TestAppRolesSyncToTheGraph(t *testing.T) {
	ctx := context.Background()
	f, rec := syncedFixture(t, authz.SyncModeStrict)
	call := func(op string, role string) string {
		return op + ":" + f.member.String() + ":" + f.org.ID.String() + ":alpha:" + role
	}
	check := func(step string, want ...string) {
		t.Helper()
		got := appCalls(rec)
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s: calls = %v, want %v", step, got, want)
		}
	}

	if _, err := f.svc.Assign(ctx, f.in(f.member, "alpha", "viewer")); err != nil {
		t.Fatal(err)
	}
	check("assign", call("AddAppRole", "viewer"))

	if _, err := f.svc.Change(ctx, f.in(f.member, "alpha", "admin")); err != nil {
		t.Fatal(err)
	}
	check("change", call("AddAppRole", "viewer"), call("AddAppRole", "admin"), call("RemoveAppRole", "viewer"))

	if _, err := f.svc.Change(ctx, f.in(f.member, "alpha", "admin")); err != nil {
		t.Fatal(err)
	}
	check("unchanged role writes nothing", call("AddAppRole", "viewer"), call("AddAppRole", "admin"), call("RemoveAppRole", "viewer"))

	if err := f.svc.Remove(ctx, f.org.ID, f.member, "alpha", f.owner); err != nil {
		t.Fatal(err)
	}
	check("remove", call("AddAppRole", "viewer"), call("AddAppRole", "admin"), call("RemoveAppRole", "viewer"), call("RemoveAppRole", "admin"))

	// RemoveForMember removes every role from the graph.
	rec2 := syncrec.New()
	f.svc = approle.NewService(f.db, authzRegistry(t), approle.EntitleAll(authzRegistry(t)), approle.WithAuthzSyncer(rec2, authz.SyncModeStrict))
	for _, app := range []string{"alpha", "beta"} {
		if _, err := f.svc.Assign(ctx, f.in(f.member, app, "viewer")); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := f.svc.RemoveForMember(ctx, f.org.ID, f.member); err != nil || n != 2 {
		t.Fatalf("RemoveForMember = %d, %v", n, err)
	}
	if got := len(appCalls(rec2)); got != 4 {
		t.Errorf("RemoveForMember: %d app calls, want 2 adds and 2 removes: %v", got, appCalls(rec2))
	}
}

func authzRegistry(t *testing.T) *authz.VocabularyRegistry {
	t.Helper()
	reg := authz.NewVocabularyRegistry()
	for _, app := range []string{"alpha", "beta"} {
		if err := reg.Register(ladderVocab{app: app}); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

func TestAppRoleSyncModes(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("graph down")

	f, rec := syncedFixture(t, authz.SyncModeStrict)
	rec.Err = boom
	if _, err := f.svc.Assign(ctx, f.in(f.member, "alpha", "viewer")); !errors.Is(err, boom) {
		t.Errorf("strict Assign = %v, want the sync error", err)
	}

	f, rec = syncedFixture(t, authz.SyncModeEventual)
	rec.Err = boom
	if _, err := f.svc.Assign(ctx, f.in(f.member, "alpha", "viewer")); err != nil {
		t.Errorf("eventual Assign = %v, want success with a logged warning", err)
	}
	stored, err := f.svc.ListForPrincipal(ctx, f.org.ID, f.member)
	if err != nil || len(stored) != 1 {
		t.Errorf("stored roles = %v, %v; the role is stored whatever the sync result", stored, err)
	}
}

// plainSyncer implements only the original RelationshipSyncer methods, as
// an existing implementer does.
type plainSyncer struct{ authz.RelationshipSyncer }

func TestSyncerWithoutAppRolesIsIgnored(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	reg := authzRegistry(t)
	var plain authz.RelationshipSyncer = plainSyncer{syncrec.New()}
	if _, ok := plain.(authz.AppRoleSyncer); ok {
		t.Fatal("test syncer unexpectedly implements AppRoleSyncer")
	}
	f.svc = approle.NewService(f.db, reg, approle.EntitleAll(reg), approle.WithAuthzSyncer(plain, authz.SyncModeStrict))
	if _, err := f.svc.Assign(ctx, f.in(f.member, "alpha", "viewer")); err != nil {
		t.Errorf("Assign with a syncer lacking app roles: %v", err)
	}
	if _, err := f.svc.Change(ctx, f.in(f.member, "alpha", "admin")); err != nil {
		t.Errorf("Change: %v", err)
	}
	if err := f.svc.Remove(ctx, f.org.ID, f.member, "alpha", f.owner); err != nil {
		t.Errorf("Remove: %v", err)
	}
}

func TestRemoveMemberSyncsAppRoleRemoval(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if _, err := f.svc.Assign(ctx, f.in(f.member, "alpha", "viewer")); err != nil {
		t.Fatal(err)
	}
	rec := syncrec.New()
	orgs := organization.NewService(f.db, organization.WithAuthzSyncer(rec))
	if err := orgs.RemoveMember(ctx, f.org.ID, f.member); err != nil {
		t.Fatal(err)
	}
	want := "RemoveAppRole:" + f.member.String() + ":" + f.org.ID.String() + ":alpha:viewer"
	if got := appCalls(rec); len(got) != 1 || got[0] != want {
		t.Errorf("calls = %v, want %v", got, want)
	}
}
