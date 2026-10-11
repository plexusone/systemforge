//go:build integration

package spicedb_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/providertest"
	"github.com/plexusone/systemforge/authz/rebac/spicedb"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/resourcegrant"

	_ "github.com/mattn/go-sqlite3"
)

// grantDemoVocabulary registers the providertest resource type with its
// standard fragment, so the deployment schema is composed from the registry
// the way an application's is.
type grantDemoVocabulary struct{}

func (grantDemoVocabulary) App() string { return "grantdemo" }
func (grantDemoVocabulary) Roles() authz.RolePermissions {
	return authz.RolePermissions{"admin": {"project.manage"}}
}
func (grantDemoVocabulary) Hierarchy() authz.RoleHierarchy { return authz.RoleHierarchy{"admin": 10} }
func (grantDemoVocabulary) Scopes() []string               { return nil }
func (grantDemoVocabulary) SpiceDBSchema() string          { return providertest.ResourceFragment() }

// TestIntegration_ResourceGrants runs the shared resource-grant suite
// against the relationship-based provider: SpiceDB (embedded, in memory)
// for permissions and lookups, the grant store on SQLite for memberships and
// grants, and the syncer mirroring one into the other. The same suite runs
// against the role-based provider in authz/rbac.
func TestIntegration_ResourceGrants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	registry := authz.NewVocabularyRegistry()
	if err := registry.Register(grantDemoVocabulary{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	schema, err := registry.ComposeSpiceDBSchema()
	if err != nil {
		t.Fatalf("compose schema: %v", err)
	}

	client, err := spicedb.NewClient(ctx, spicedb.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("failed to create SpiceDB client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := client.WriteSchema(ctx, schema); err != nil {
		t.Fatalf("failed to write schema: %v", err)
	}

	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	syncer := spicedb.NewSyncer(client)
	orgs := organization.NewService(db, organization.WithAuthzSyncer(syncer), organization.WithSyncMode(authz.SyncModeStrict))
	store := resourcegrant.NewService(db,
		resourcegrant.WithVocabularies(registry),
		resourcegrant.WithAuthzSyncer(syncer, authz.SyncModeStrict),
	)
	provider := spicedb.NewProvider(client, spicedb.WithResourceGrants(store))

	providertest.RunResourceGrantTests(t, providertest.Config{
		Provider:        provider,
		ResourceGranter: provider,
		NewPrincipal: func(t *testing.T) uuid.UUID {
			t.Helper()
			p, err := db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("P").Save(ctx)
			if err != nil {
				t.Fatalf("principal: %v", err)
			}
			return p.ID
		},
		NewOrganization: func(t *testing.T) uuid.UUID {
			t.Helper()
			org, err := orgs.Create(ctx, organization.CreateOrganizationInput{Name: "Org", Slug: "org-" + uuid.NewString()[:8], OrgType: organization.OrgTypeTeam})
			if err != nil {
				t.Fatalf("organization: %v", err)
			}
			return org.ID
		},
		GrantOrgRole: func(t *testing.T, orgID, principalID uuid.UUID, role string) {
			t.Helper()
			if _, err := orgs.AddMember(ctx, organization.AddMemberInput{OrganizationID: orgID, PrincipalID: principalID, Role: role}); err != nil {
				t.Fatalf("AddMember: %v", err)
			}
		},
		// The application writes a resource's org relation when it creates
		// the resource.
		RegisterResource: func(t *testing.T, ref authz.ResourceRef) {
			t.Helper()
			if err := provider.AddRelationship(ctx, spicedb.TypeOrganization, ref.OrganizationID.String(), "org", ref.Type, ref.ID); err != nil {
				t.Fatalf("link resource to its organization: %v", err)
			}
		},
	})
}

// TestIntegration_GrantRelationships checks the relationships the syncer
// writes: one role per principal and resource, replaced atomically, and
// removed with the grant.
func TestIntegration_GrantRelationships(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := spicedb.NewClient(ctx, spicedb.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("failed to create SpiceDB client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := client.WriteSchema(ctx, authz.BaseSpiceDBSchema+"\n"+providertest.ResourceFragment()); err != nil {
		t.Fatalf("failed to write schema: %v", err)
	}
	syncer := spicedb.NewSyncer(client)
	provider := spicedb.NewProvider(client)

	who, org := uuid.New(), uuid.New()
	ref := authz.ResourceRef{Type: providertest.ResourceType, ID: uuid.NewString(), OrganizationID: org}
	id := uuid.MustParse(ref.ID)
	resource := authz.Resource{Type: providertest.ResourceType, ID: &id}
	can := func(action authz.Action) bool {
		t.Helper()
		ok, err := provider.Can(ctx, authz.NewUserPrincipal(who), action, resource)
		if err != nil {
			t.Fatalf("Can(%s): %v", action, err)
		}
		return ok
	}

	for _, role := range []string{authz.ResourceRoleViewer, authz.ResourceRoleMaintainer, authz.ResourceRoleContributor} {
		if err := syncer.SetResourceGrant(ctx, who, ref, role); err != nil {
			t.Fatalf("SetResourceGrant(%s): %v", role, err)
		}
		// Exactly the role's permissions: a lower role replaces a higher.
		for _, p := range []authz.Action{authz.PermResourceView, authz.PermResourceEdit, authz.PermResourceManage} {
			if got, want := can(p), authz.ResourceRoleAllows(role, p); got != want {
				t.Errorf("after setting %s: Can(%s) = %v, want %v", role, p, got, want)
			}
		}
	}
	// Setting the same role again is idempotent.
	if err := syncer.SetResourceGrant(ctx, who, ref, authz.ResourceRoleContributor); err != nil {
		t.Fatalf("SetResourceGrant again: %v", err)
	}
	if !can(authz.PermResourceEdit) {
		t.Error("an idempotent set lost the grant")
	}

	// LookupResources agrees with Can.
	set, err := provider.ListResources(ctx, who, providertest.ResourceType, authz.PermResourceEdit)
	if err != nil || !slices.Equal(set.IDs, []string{ref.ID}) {
		t.Errorf("ListResources(edit) = %+v, %v; want [%s]", set, err, ref.ID)
	}
	if set, err = provider.ListResources(ctx, who, providertest.ResourceType, authz.PermResourceManage); err != nil || len(set.IDs) != 0 {
		t.Errorf("ListResources(manage) = %+v, %v; want none", set, err)
	}
	if _, err = provider.ListResources(ctx, who, providertest.ResourceType, "delete"); err == nil {
		t.Error("ListResources accepted a permission that is not view, edit or manage")
	}

	if err := syncer.RemoveResourceGrant(ctx, who, ref); err != nil {
		t.Fatalf("RemoveResourceGrant: %v", err)
	}
	if can(authz.PermResourceView) {
		t.Error("a removed grant still grants view")
	}
	// Removing what is not there is not an error.
	if err := syncer.RemoveResourceGrant(ctx, who, ref); err != nil {
		t.Errorf("second RemoveResourceGrant: %v", err)
	}

	// The syncer refuses what the graph must not hold.
	if err := syncer.SetResourceGrant(ctx, who, ref, "admin"); err == nil {
		t.Error("SetResourceGrant accepted admin")
	}
	if err := syncer.SetResourceGrant(ctx, who, authz.ResourceRef{Type: "project", ID: "1"}, authz.ResourceRoleViewer); err == nil {
		t.Error("SetResourceGrant accepted a type with no application prefix")
	}
}
