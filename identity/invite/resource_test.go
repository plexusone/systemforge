package invite_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/resourcegrant"
	"github.com/plexusone/systemforge/identity/invite"
	"github.com/plexusone/systemforge/identity/organization"
	grants "github.com/plexusone/systemforge/identity/resourcegrant"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// shareVocab is an application whose projects accept collaborators.
type shareVocab struct{}

func (shareVocab) App() string { return "share" }
func (shareVocab) Roles() authz.RolePermissions {
	return authz.RolePermissions{"admin": {"project.manage"}}
}
func (shareVocab) Hierarchy() authz.RoleHierarchy { return authz.RoleHierarchy{"admin": 10} }
func (shareVocab) Scopes() []string               { return nil }
func (shareVocab) SpiceDBSchema() string          { return authz.ResourceRoleFragment("share_project") }

type resourceFixture struct {
	t        *testing.T
	ctx      context.Context
	db       *ent.Client
	svc      invite.Service
	rec      *syncrec.Recorder
	org      uuid.UUID
	personal uuid.UUID
	owner    uuid.UUID
}

func newResourceFixture(t *testing.T) *resourceFixture {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	registry := authz.NewVocabularyRegistry()
	if err := registry.Register(shareVocab{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	rec := syncrec.New()
	store := grants.NewService(db, grants.WithVocabularies(registry), grants.WithAuthzSyncer(rec, authz.SyncModeStrict))
	svc := invite.NewService(db, "https://app.example.com",
		invite.WithResourceGrants(store), invite.WithAuthzSyncer(rec), invite.WithSyncMode(authz.SyncModeStrict))
	orgID, owner := seedInviteOrg(t, db)
	personal, err := organization.NewService(db).Create(context.Background(), organization.CreateOrganizationInput{
		Name: "Me", Slug: "me-" + uuid.NewString()[:8], OrgType: organization.OrgTypePersonal, OwnerPrincipalID: &owner,
	})
	if err != nil {
		t.Fatalf("personal organization: %v", err)
	}
	return &resourceFixture{t: t, ctx: context.Background(), db: db, svc: svc, rec: rec, org: orgID, personal: personal.ID, owner: owner}
}

func (f *resourceFixture) person() uuid.UUID {
	f.t.Helper()
	p, err := f.db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("P").Save(f.ctx)
	if err != nil {
		f.t.Fatalf("principal: %v", err)
	}
	return p.ID
}

func (f *resourceFixture) create(org uuid.UUID, email, id, role string) (*invite.InviteResult, error) {
	return f.svc.Create(f.ctx, invite.CreateInviteInput{
		OrganizationID: org, InviterPrincipalID: f.owner, Email: email, Role: organization.RoleCollaborator,
		ResourceType: "share_project", ResourceID: id, ResourceRole: role,
	})
}

func (f *resourceFixture) role(who, org uuid.UUID) string {
	f.t.Helper()
	m, err := f.db.PrincipalMembership.Query().Where(principalmembership.PrincipalID(who), principalmembership.OrganizationID(org)).Only(f.ctx)
	if ent.IsNotFound(err) {
		return ""
	}
	if err != nil {
		f.t.Fatalf("membership: %v", err)
	}
	return m.Role
}

func (f *resourceFixture) grantRole(who uuid.UUID, typ, id string) string {
	f.t.Helper()
	g, err := f.db.ResourceGrant.Query().Where(resourcegrant.PrincipalID(who), resourcegrant.ResourceType(typ), resourcegrant.ResourceID(id)).Only(f.ctx)
	if ent.IsNotFound(err) {
		return ""
	}
	if err != nil {
		f.t.Fatalf("grant: %v", err)
	}
	return g.Role
}

// TestResourceInviteAcceptCreatesMembershipAndGrant covers the happy path
// in a team and in a personal organization.
func TestResourceInviteAcceptCreatesMembershipAndGrant(t *testing.T) {
	f := newResourceFixture(t)
	for name, org := range map[string]uuid.UUID{"team": f.org, "personal": f.personal} {
		t.Run(name, func(t *testing.T) {
			who := f.person()
			res, err := f.create(org, who.String()+"@example.com", "p-"+name, authz.ResourceRoleContributor)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			inv := res.Invite
			if inv.ResourceType != "share_project" || inv.ResourceID != "p-"+name || inv.ResourceRole != "contributor" || inv.Role != "collaborator" {
				t.Errorf("invite = %+v", inv)
			}
			before := len(f.rec.Calls())
			if _, err := f.svc.Accept(f.ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: who}); err != nil {
				t.Fatalf("Accept: %v", err)
			}
			if got := f.role(who, org); got != "collaborator" {
				t.Errorf("membership = %q, want collaborator", got)
			}
			if got := f.grantRole(who, "share_project", "p-"+name); got != "contributor" {
				t.Errorf("grant = %q, want contributor", got)
			}
			calls := f.rec.Calls()[before:]
			wantGrant := fmt.Sprintf("SetResourceGrant:%s:%s:share_project:p-%s:contributor", who, org, name)
			wantMember := fmt.Sprintf("AddOrgMembership:%s:%s:collaborator", who, org)
			if !slices.Contains(calls, wantGrant) || !slices.Contains(calls, wantMember) {
				t.Errorf("syncer calls %v lack %s or %s", calls, wantMember, wantGrant)
			}
			got, err := f.svc.GetByID(f.ctx, inv.ID)
			if err != nil || got.Status != invite.StatusAccepted {
				t.Errorf("invite after accept = %+v, %v", got, err)
			}
		})
	}
}

// TestResourceInviteToExistingMember lets a member accept a resource
// invitation: they keep their role and gain the grant.
func TestResourceInviteToExistingMember(t *testing.T) {
	f := newResourceFixture(t)
	who := f.person()
	if _, err := f.db.PrincipalMembership.Create().SetPrincipalID(who).SetOrganizationID(f.org).SetRole("member").Save(f.ctx); err != nil {
		t.Fatalf("membership: %v", err)
	}
	res, err := f.create(f.org, "member@example.com", "p1", authz.ResourceRoleMaintainer)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := f.svc.Accept(f.ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: who}); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got := f.role(who, f.org); got != "member" {
		t.Errorf("membership = %q, want member kept", got)
	}
	if got := f.grantRole(who, "share_project", "p1"); got != "maintainer" {
		t.Errorf("grant = %q, want maintainer", got)
	}
}

// TestResourceInviteAcceptIsAtomic checks that a grant the store refuses
// leaves no membership, no grant and a pending invite.
func TestResourceInviteAcceptIsAtomic(t *testing.T) {
	f := newResourceFixture(t)
	// The resource already belongs to the personal organization, so a grant
	// naming the team organization is refused.
	if err := grants.NewService(f.db).GrantResourceRole(f.ctx, f.owner, authz.ResourceRef{Type: "share_project", ID: "taken", OrganizationID: f.personal}, authz.ResourceRoleViewer, uuid.Nil); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	who := f.person()
	res, err := f.create(f.org, "x@example.com", "taken", authz.ResourceRoleViewer)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err = f.svc.Accept(f.ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: who})
	if !errors.Is(err, authz.ErrResourceOrganizationMismatch) {
		t.Fatalf("Accept = %v, want ErrResourceOrganizationMismatch", err)
	}
	if got := f.role(who, f.org); got != "" {
		t.Errorf("membership after a failed accept = %q, want none", got)
	}
	if got := f.grantRole(who, "share_project", "taken"); got != "" {
		t.Errorf("grant after a failed accept = %q, want none", got)
	}
	got, err := f.svc.GetByID(f.ctx, res.Invite.ID)
	if err != nil || got.Status != invite.StatusPending {
		t.Errorf("invite after a failed accept = %+v, %v; want pending", got, err)
	}
}

// TestResourceInviteValidation covers the refusals of Create.
func TestResourceInviteValidation(t *testing.T) {
	f := newResourceFixture(t)
	create := func(role, typ, id, resRole string) error {
		_, err := f.svc.Create(f.ctx, invite.CreateInviteInput{
			OrganizationID: f.org, InviterPrincipalID: f.owner, Email: uuid.NewString() + "@example.com", Role: role,
			ResourceType: typ, ResourceID: id, ResourceRole: resRole,
		})
		return err
	}
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"incomplete: no id":       {create("collaborator", "share_project", "", "viewer"), invite.ErrResourceInvite},
		"incomplete: no role":     {create("collaborator", "share_project", "p", ""), invite.ErrResourceInvite},
		"not a collaborator":      {create("member", "share_project", "p", "viewer"), invite.ErrResourceInvite},
		"bad resource role":       {create("collaborator", "share_project", "p", "editor"), authz.ErrInvalidResourceRole},
		"unregistered type":       {create("collaborator", "other_project", "p", "viewer"), authz.ErrInvalidResource},
		"type without the ladder": {create("collaborator", "share_org", "p", "viewer"), authz.ErrInvalidResource},
		"bad id":                  {create("collaborator", "share_project", "a b", "viewer"), authz.ErrInvalidResource},
	} {
		if !errors.Is(tc.err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, tc.err, tc.want)
		}
	}

	// A service without a grant store refuses targets.
	plain := invite.NewService(f.db, "https://app.example.com")
	_, err := plain.Create(f.ctx, invite.CreateInviteInput{OrganizationID: f.org, InviterPrincipalID: f.owner, Email: "p@example.com", Role: "collaborator", ResourceType: "share_project", ResourceID: "p", ResourceRole: "viewer"})
	if !errors.Is(err, invite.ErrResourceInvite) {
		t.Errorf("without a grant store: %v, want ErrResourceInvite", err)
	}
}

// TestResourceInvitesToOnePerson checks that one person may hold a pending
// invite to several resources, but not two to the same one.
func TestResourceInvitesToOnePerson(t *testing.T) {
	f := newResourceFixture(t)
	email := "multi@example.com"
	if _, err := f.create(f.org, email, "a", "viewer"); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := f.create(f.org, email, "b", "viewer"); err != nil {
		t.Errorf("second resource: %v", err)
	}
	if _, err := f.create(f.org, email, "a", "maintainer"); err == nil || !strings.Contains(err.Error(), "pending invite") {
		t.Errorf("same resource twice: %v, want a pending-invite refusal", err)
	}
	// An organization invite is separate from resource invites.
	if _, err := f.svc.Create(f.ctx, invite.CreateInviteInput{OrganizationID: f.org, InviterPrincipalID: f.owner, Email: email, Role: "member"}); err != nil {
		t.Errorf("organization invite beside resource invites: %v", err)
	}
}

// TestResourceInviteAPI creates a resource invite over HTTP and reads the
// target back.
func TestResourceInviteAPI(t *testing.T) {
	a := newInviteAPI(t, func(db *ent.Client) invite.ServiceOption {
		registry := authz.NewVocabularyRegistry()
		if err := registry.Register(shareVocab{}); err != nil {
			t.Fatalf("register: %v", err)
		}
		return invite.WithResourceGrants(grants.NewService(db, grants.WithVocabularies(registry)))
	})
	path := "/organizations/acme/invites"
	code, body := a.do(http.MethodPost, path, "owner", map[string]any{
		"email": "api@example.com", "role": "collaborator",
		"resource_type": "share_project", "resource_id": "p9", "resource_role": "viewer",
	})
	if code != http.StatusCreated || !strings.Contains(string(body), `"resource_id":"p9"`) || !strings.Contains(string(body), `"resource_role":"viewer"`) {
		t.Errorf("create = %d %s", code, body)
	}
	code, _ = a.do(http.MethodPost, path, "owner", map[string]any{
		"email": "api2@example.com", "role": "member", "resource_type": "share_project", "resource_id": "p9", "resource_role": "viewer",
	})
	if code != http.StatusBadRequest {
		t.Errorf("a resource invite for a member = %d, want 400", code)
	}
	code, _ = a.do(http.MethodPost, path, "owner", map[string]any{
		"email": "api3@example.com", "role": "collaborator", "resource_type": "share_project", "resource_id": "p9", "resource_role": "owner",
	})
	if code != http.StatusUnprocessableEntity {
		t.Errorf("an unknown resource role = %d, want 422", code)
	}
}
