package rbac_test

import (
	"context"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/providertest"
	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/resourcegrant"
	"github.com/plexusone/systemforge/internal/pgtest"

	_ "github.com/mattn/go-sqlite3"
)

// grantProvider builds the role-based provider over an in-memory database
// with the grant store, the way an application wires it.
func grantProvider(t *testing.T, db *ent.Client) (*rbac.Provider, organization.Service) {
	t.Helper()
	registry := authz.NewVocabularyRegistry()
	orgs := organization.NewService(db)
	grants := resourcegrant.NewService(db, resourcegrant.WithVocabularies(demoRegistry(t, registry)))
	// The organization ladder through the standard resource permissions:
	// an admin or owner manages, a member views.
	perms := authz.RolePermissions{}
	for role, perm := range map[string][]string{
		"owner":  {"view", "edit", "manage"},
		"admin":  {"view", "edit", "manage"},
		"member": {"view"},
	} {
		for _, p := range perm {
			perms[role] = append(perms[role], providertest.ResourceType+"."+p)
		}
	}
	provider := rbac.New(
		rbac.WithRoleGetter(organization.MembershipRoleGetter(orgs)),
		rbac.WithPermissions(perms),
		rbac.WithResourceGrants(grants),
	)
	return provider, orgs
}

type demoVocabulary struct{}

func (demoVocabulary) App() string { return "grantdemo" }
func (demoVocabulary) Roles() authz.RolePermissions {
	return authz.RolePermissions{"admin": {"project.manage"}}
}
func (demoVocabulary) Hierarchy() authz.RoleHierarchy { return authz.RoleHierarchy{"admin": 10} }
func (demoVocabulary) Scopes() []string               { return nil }
func (demoVocabulary) SpiceDBSchema() string          { return "" }

func demoRegistry(t *testing.T, r *authz.VocabularyRegistry) *authz.VocabularyRegistry {
	t.Helper()
	if err := r.Register(demoVocabulary{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	return r
}

// TestResourceGrantConformance runs the resource-grant suite against the
// role-based provider. The relationship-based provider runs the same suite
// in its integration tests.
func TestResourceGrantConformance(t *testing.T) {
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	runConformance(t, db)
}

// TestResourceGrantConformancePostgres runs the suite on PostgreSQL, where
// the unique keys, foreign keys and locks are the database's own.
func TestResourceGrantConformancePostgres(t *testing.T) {
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
	runConformance(t, db)
}

func runConformance(t *testing.T, db *ent.Client) {
	t.Helper()
	provider, orgs := grantProvider(t, db)
	ctx := context.Background()
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
	})
}

// TestWithoutResourceGrants checks that a provider built without a grant
// store answers as before and refuses the grant operations clearly.
func TestWithoutResourceGrants(t *testing.T) {
	p := rbac.New()
	ctx := context.Background()
	ref := authz.ResourceRef{Type: "grantdemo_project", ID: "p1", OrganizationID: uuid.New()}
	if err := p.GrantResourceRole(ctx, uuid.New(), ref, authz.ResourceRoleViewer, uuid.Nil); err != rbac.ErrNoResourceGrants {
		t.Errorf("GrantResourceRole = %v, want ErrNoResourceGrants", err)
	}
	if _, err := p.ListResources(ctx, uuid.New(), ref.Type, authz.PermResourceView); err != rbac.ErrNoResourceGrants {
		t.Errorf("ListResources = %v, want ErrNoResourceGrants", err)
	}
	id := uuid.New()
	org := uuid.New()
	ok, err := p.Can(ctx, authz.NewUserPrincipal(uuid.New()), authz.PermResourceView, authz.Resource{Type: "grantdemo_project", ID: &id, OrgID: &org})
	if err != nil || ok {
		t.Errorf("Can without grants = %v, %v", ok, err)
	}
}
