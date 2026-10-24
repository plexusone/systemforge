package mode_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/mode"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"

	_ "github.com/mattn/go-sqlite3"
)

// demoVocabulary is an application whose projects accept collaborators.
type demoVocabulary struct{}

func (demoVocabulary) App() string { return "modedemo" }
func (demoVocabulary) Roles() authz.RolePermissions {
	return authz.RolePermissions{"admin": {"project.manage"}}
}
func (demoVocabulary) Hierarchy() authz.RoleHierarchy { return authz.RoleHierarchy{"admin": 10} }
func (demoVocabulary) Scopes() []string               { return nil }
func (demoVocabulary) SpiceDBSchema() string          { return authz.ResourceRoleFragment("modedemo_project") }

func newDB(t *testing.T) *ent.Client {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return db
}

func newRegistry(t *testing.T) *authz.VocabularyRegistry {
	t.Helper()
	r := authz.NewVocabularyRegistry()
	if err := r.Register(demoVocabulary{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	return r
}

// exerciseContract runs the collaborator lifecycle through a configured
// mode: grant, check, list, revoke.
func exerciseContract(t *testing.T, db *ent.Client, res *mode.Result, linkResource func(org uuid.UUID, id string)) {
	t.Helper()
	ctx := context.Background()
	person := func() uuid.UUID {
		p, err := db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("P").Save(ctx)
		if err != nil {
			t.Fatalf("principal: %v", err)
		}
		return p.ID
	}
	owner, collaborator := person(), person()
	orgs := organization.NewService(db, organization.WithAuthzSyncer(res.Syncer), organization.WithSyncMode(authz.SyncModeStrict))
	org, err := orgs.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme-" + uuid.NewString()[:8], OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatalf("organization: %v", err)
	}
	ref := authz.ResourceRef{Type: "modedemo_project", ID: uuid.NewString(), OrganizationID: org.ID}
	linkResource(org.ID, ref.ID)
	id := uuid.MustParse(ref.ID)
	resource := authz.Resource{Type: "modedemo_project", ID: &id, OrgID: &org.ID}
	can := func(who uuid.UUID, a authz.Action) bool {
		t.Helper()
		ok, err := res.Provider.Can(ctx, authz.NewUserPrincipal(who), a, resource)
		if err != nil {
			t.Fatalf("Can(%s): %v", a, err)
		}
		return ok
	}

	if can(collaborator, authz.PermResourceView) {
		t.Fatal("a stranger can view the resource")
	}
	if err := res.Provider.GrantResourceRole(ctx, collaborator, ref, authz.ResourceRoleContributor, owner); err != nil {
		t.Fatalf("GrantResourceRole: %v", err)
	}
	if !can(collaborator, authz.PermResourceView) || !can(collaborator, authz.PermResourceEdit) || can(collaborator, authz.PermResourceManage) {
		t.Error("a contributor's permissions are not view and edit")
	}
	set, err := res.Provider.ListResources(ctx, collaborator, "modedemo_project", authz.PermResourceEdit)
	if err != nil || len(set.IDs) != 1 || set.IDs[0] != ref.ID {
		t.Errorf("ListResources = %+v, %v", set, err)
	}
	if role, err := res.Provider.GetRole(ctx, authz.NewUserPrincipal(collaborator), org.ID); err != nil || role != "collaborator" {
		t.Errorf("organization role = %q, %v; want collaborator", role, err)
	}
	if err := res.Provider.RevokeResourceRole(ctx, collaborator, ref); err != nil {
		t.Fatalf("RevokeResourceRole: %v", err)
	}
	if can(collaborator, authz.PermResourceView) {
		t.Error("a revoked collaborator can still view the resource")
	}
}

func TestNewRBAC(t *testing.T) {
	db := newDB(t)
	// The zero configuration is mode rbac.
	res, err := mode.New(context.Background(), authz.ModeConfig{}, mode.Deps{DB: db, Registry: newRegistry(t)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := res.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if res.Mode != authz.ModeRBAC {
		t.Errorf("mode = %q", res.Mode)
	}
	if _, ok := res.Provider.(*rbac.Provider); !ok {
		t.Errorf("provider is %T, want *rbac.Provider", res.Provider)
	}
	if _, ok := res.Provider.(authz.DecisionAuthorizer); !ok {
		t.Error("the role-based provider does not implement DecisionAuthorizer")
	}
	if _, ok := res.Syncer.(*noop.Syncer); !ok {
		t.Errorf("syncer is %T, want the no-op syncer", res.Syncer)
	}
	if res.Grants == nil {
		t.Error("no grant store")
	}
	if res.Reconciler != nil {
		t.Error("mode rbac has a graph reconciler")
	}
	if err := res.RunReconciler(context.Background()); err != nil {
		t.Errorf("RunReconciler in mode rbac = %v", err)
	}
	// The member's access to the resource reaches through the permission
	// map; this test grants only directly.
	exerciseContract(t, db, res, func(uuid.UUID, string) {})
}

func TestNewRejects(t *testing.T) {
	ctx := context.Background()
	if _, err := mode.New(ctx, authz.ModeConfig{}, mode.Deps{}); err == nil {
		t.Error("New without a database succeeded")
	}
	db := newDB(t)
	for name, cfg := range map[string]authz.ModeConfig{
		"unknown mode":        {Mode: "abac"},
		"engine with rbac":    {Mode: authz.ModeRBAC, Engine: authz.EngineSpiceDB},
		"unknown engine":      {Mode: authz.ModeReBAC, Engine: "openfga"},
		"remote no endpoint":  {Mode: authz.ModeReBAC, SpiceDB: &authz.SpiceDBConfig{Mode: "remote"}},
		"reconcile with rbac": {Mode: authz.ModeRBAC, Reconcile: &authz.ReconcileConfig{}},
		"bad interval":        {Mode: authz.ModeReBAC, Reconcile: &authz.ReconcileConfig{Interval: "soon"}},
	} {
		if res, err := mode.New(ctx, cfg, mode.Deps{DB: db}); err == nil {
			_ = res.Close()
			t.Errorf("%s: New succeeded", name)
		}
	}
}
