package systemauth

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/identity/serviceaccount"
)

// saVocab declares the roles of the test application "billing".
type saVocab struct{}

func (saVocab) App() string { return "billing" }
func (saVocab) Roles() authz.RolePermissions {
	return authz.RolePermissions{"viewer": {"invoice.read"}, "admin": {"invoice.read", "app.admin"}}
}
func (saVocab) Hierarchy() authz.RoleHierarchy {
	return authz.RoleHierarchy{"viewer": 10, "admin": 40}
}
func (saVocab) Scopes() []string      { return nil }
func (saVocab) SpiceDBSchema() string { return "" }

// saFixture is an identity database with a team organization and the
// service-account service over it.
type saFixture struct {
	t         *testing.T
	db        *ent.Client
	svc       *serviceaccount.Service
	roles     *approle.Service
	orgs      organization.Service
	org       *organization.Organization
	owner     uuid.UUID
	announced []accesschange.Change
}

func newSAFixture(t *testing.T) *saFixture {
	t.Helper()
	ctx := context.Background()
	db := newEntTestClient(t, uuid.NewString())
	f := &saFixture{t: t, db: db, orgs: organization.NewService(db)}
	sink := accesschange.SinkFunc(func(c accesschange.Change) { f.announced = append(f.announced, c) })
	reg := authz.NewVocabularyRegistry()
	if err := reg.Register(saVocab{}); err != nil {
		t.Fatal(err)
	}
	f.roles = approle.NewService(db, reg, approle.EntitleAll(reg), approle.WithAccessChangeSink(sink))
	svc, err := serviceaccount.New(serviceaccount.Config{
		Client:           db,
		Principals:       principal.NewService(db, principal.WithAccessChangeSink(sink)),
		Roles:            f.roles,
		AccessChangeSink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	owner, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier("owner@example.com").SetDisplayName("Owner").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.owner = owner.ID
	org, err := f.orgs.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &f.owner})
	if err != nil {
		t.Fatal(err)
	}
	f.org = org
	return f
}

// account creates a service account with scopes.
func (f *saFixture) account(name string, scopes ...string) *serviceaccount.Account {
	f.t.Helper()
	acct, err := f.svc.Create(context.Background(), serviceaccount.CreateInput{OrganizationID: f.org.ID, Name: name, Scopes: scopes, CreatedBy: f.owner})
	if err != nil {
		f.t.Fatalf("create account: %v", err)
	}
	return acct
}

// key adds a key to the account: generated when in is empty.
func (f *saFixture) key(acct *serviceaccount.Account, in serviceaccount.KeyInput) *serviceaccount.Key {
	f.t.Helper()
	k, err := f.svc.AddKey(context.Background(), acct.ID, in)
	if err != nil {
		f.t.Fatalf("add key: %v", err)
	}
	return k
}
