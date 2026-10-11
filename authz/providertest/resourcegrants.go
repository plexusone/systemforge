package providertest

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
)

// ResourceType is the resource type RunResourceGrantTests grants on. A
// provider whose rules come from a schema must declare it with
// ResourceFragment; the relationship-based provider's schema is the base
// schema followed by it.
const ResourceType = "grantdemo_project"

// ResourceFragment is the SpiceDB definition of ResourceType: the standard
// collaborator-able resource of authz.ResourceRoleFragment.
func ResourceFragment() string {
	return authz.ResourceRoleFragment(ResourceType)
}

// RunResourceGrantTests checks the resource-grant contract (ADR-008):
// grants, role replacement, reductions, revocation, the collaborator
// membership a first grant creates and the last revoke removes, what a
// collaborator may and may not do on the organization, and ListResources
// for each permission. The same suite runs against the role-based and the
// relationship-based provider, which is what makes the two modes
// interchangeable on the contract.
//
// It requires cfg.Provider, cfg.ResourceGranter and cfg.GrantOrgRole. The
// role-based provider's permission map must grant "grantdemo_project.view"
// to member and "grantdemo_project.{view,edit,manage}" to admin and owner,
// as the standard resource fragment does through the organization.
func RunResourceGrantTests(t *testing.T, cfg Config) {
	t.Helper()
	cfg = cfg.withDefaults()
	switch {
	case cfg.ResourceGranter == nil:
		t.Fatal("providertest: RunResourceGrantTests requires Config.ResourceGranter")
	case cfg.GrantOrgRole == nil:
		t.Fatal("providertest: RunResourceGrantTests requires Config.GrantOrgRole")
	}
	t.Run("Resource_Grants", func(t *testing.T) { testResourceGrants(t, cfg) })
}

// resourceEnv bundles what the cases share.
type resourceEnv struct {
	t   *testing.T
	ctx context.Context
	cfg Config
}

func (e *resourceEnv) principal() uuid.UUID {
	e.t.Helper()
	if e.cfg.NewPrincipal != nil {
		return e.cfg.NewPrincipal(e.t)
	}
	return uuid.New()
}

func (e *resourceEnv) organization() uuid.UUID {
	e.t.Helper()
	if e.cfg.NewOrganization != nil {
		return e.cfg.NewOrganization(e.t)
	}
	return uuid.New()
}

func (e *resourceEnv) resource(org uuid.UUID) authz.ResourceRef {
	e.t.Helper()
	ref := authz.ResourceRef{Type: ResourceType, ID: uuid.NewString(), OrganizationID: org}
	if e.cfg.RegisterResource != nil {
		e.cfg.RegisterResource(e.t, ref)
	}
	return ref
}

// can reports whether the principal holds action on the resource.
func (e *resourceEnv) can(who uuid.UUID, action authz.Action, ref authz.ResourceRef) bool {
	e.t.Helper()
	id, err := uuid.Parse(ref.ID)
	if err != nil {
		e.t.Fatalf("resource id %q: %v", ref.ID, err)
	}
	res := authz.Resource{Type: authz.ResourceType(ref.Type), ID: &id, OrgID: &ref.OrganizationID}
	ok, err := e.cfg.Provider.Can(e.ctx, authz.NewUserPrincipal(who), action, res)
	if err != nil {
		e.t.Fatalf("Can(%s): %v", action, err)
	}
	return ok
}

func (e *resourceEnv) canOrg(who, org uuid.UUID, action authz.Action) bool {
	e.t.Helper()
	ok, err := e.cfg.Provider.Can(e.ctx, authz.NewUserPrincipal(who), action, authz.NewResourceWithID(authz.ResourceTypeOrganization, org))
	if err != nil {
		e.t.Fatalf("Can(%s) on organization: %v", action, err)
	}
	return ok
}

// covers reports whether a ListResources answer includes the resource,
// directly or through its organization, as an application applies it.
func covers(set authz.ResourceSet, ref authz.ResourceRef) bool {
	return slices.Contains(set.IDs, ref.ID) || slices.Contains(set.OrganizationIDs, ref.OrganizationID)
}

func (e *resourceEnv) lists(who uuid.UUID, permission authz.Action) authz.ResourceSet {
	e.t.Helper()
	set, err := e.cfg.ResourceGranter.ListResources(e.ctx, who, ResourceType, permission)
	if err != nil {
		e.t.Fatalf("ListResources(%s): %v", permission, err)
	}
	return set
}

func (e *resourceEnv) grant(who uuid.UUID, ref authz.ResourceRef, role string) {
	e.t.Helper()
	if err := e.cfg.ResourceGranter.GrantResourceRole(e.ctx, who, ref, role, uuid.Nil); err != nil {
		e.t.Fatalf("GrantResourceRole(%s): %v", role, err)
	}
}

func (e *resourceEnv) revoke(who uuid.UUID, ref authz.ResourceRef) {
	e.t.Helper()
	if err := e.cfg.ResourceGranter.RevokeResourceRole(e.ctx, who, ref); err != nil {
		e.t.Fatalf("RevokeResourceRole: %v", err)
	}
}

// orgRole returns the principal's organization role, when the provider can
// report it.
func (e *resourceEnv) orgRole(who, org uuid.UUID) (string, bool) {
	e.t.Helper()
	if e.cfg.OrgProvider == nil {
		return "", false
	}
	role, err := e.cfg.OrgProvider.GetRole(e.ctx, authz.NewUserPrincipal(who), org)
	if err != nil {
		e.t.Fatalf("GetRole: %v", err)
	}
	return role, true
}

func testResourceGrants(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.SetupFunc != nil {
		cfg.SetupFunc(t)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	t.Run("collaborator_ladder", func(t *testing.T) {
		e := &resourceEnv{t: t, ctx: ctx, cfg: cfg}
		org, other := e.organization(), e.organization()
		res, sibling, foreign := e.resource(org), e.resource(org), e.resource(other)
		who := e.principal()

		// No grant, no access.
		for _, p := range []authz.Action{authz.PermResourceView, authz.PermResourceEdit, authz.PermResourceManage} {
			if e.can(who, p, res) {
				t.Errorf("a stranger holds %s", p)
			}
		}

		// The first grant makes the principal a collaborator.
		e.grant(who, res, authz.ResourceRoleViewer)
		if role, ok := e.orgRole(who, org); ok && role != "collaborator" {
			t.Errorf("organization role after the first grant = %q, want collaborator", role)
		}
		want := func(label string, ref authz.ResourceRef, view, edit, manage bool) {
			t.Helper()
			for p, w := range map[authz.Action]bool{authz.PermResourceView: view, authz.PermResourceEdit: edit, authz.PermResourceManage: manage} {
				if got := e.can(who, p, ref); got != w {
					t.Errorf("%s: Can(%s) = %v, want %v", label, p, got, w)
				}
			}
		}
		want("viewer", res, true, false, false)
		want("sibling resource", sibling, false, false, false)
		want("resource of another organization", foreign, false, false, false)

		// A collaborator has list on the organization and nothing else.
		for _, p := range authz.OrgRolePermissions["owner"] {
			if got, w := e.canOrg(who, org, p), p == authz.PermOrgList; got != w {
				t.Errorf("collaborator Can(%s) on the organization = %v, want %v", p, got, w)
			}
		}
		if e.canOrg(who, other, authz.PermOrgList) {
			t.Error("a collaborator lists an organization it has no grant in")
		}

		// The ladder: each role includes the ones below it.
		e.grant(who, res, authz.ResourceRoleContributor)
		want("contributor", res, true, true, false)
		e.grant(who, res, authz.ResourceRoleMaintainer)
		want("maintainer", res, true, true, true)

		// A grant replaces the role; a reduction takes effect.
		e.grant(who, res, authz.ResourceRoleViewer)
		want("reduced to viewer", res, true, false, false)
		grants, err := cfg.ResourceGranter.ListResourceGrants(ctx, res)
		if err != nil {
			t.Fatalf("ListResourceGrants: %v", err)
		}
		if len(grants) != 1 || grants[0].PrincipalID != who || grants[0].Role != authz.ResourceRoleViewer || grants[0].Resource.ID != res.ID {
			t.Errorf("ListResourceGrants = %+v, want one viewer grant", grants)
		}

		// ListResources, for each permission.
		e.grant(who, sibling, authz.ResourceRoleContributor)
		for _, tc := range []struct {
			permission authz.Action
			res, sib   bool
		}{
			{authz.PermResourceView, true, true},
			{authz.PermResourceEdit, false, true},
			{authz.PermResourceManage, false, false},
		} {
			set := e.lists(who, tc.permission)
			if covers(set, res) != tc.res || covers(set, sibling) != tc.sib || covers(set, foreign) {
				t.Errorf("ListResources(%s) = %+v: covers resource=%v sibling=%v foreign=%v, want %v %v false",
					tc.permission, set, covers(set, res), covers(set, sibling), covers(set, foreign), tc.res, tc.sib)
			}
		}

		// Revoking one grant keeps the collaborator and their other grant.
		e.revoke(who, res)
		want("revoked", res, false, false, false)
		want("remaining grant", sibling, true, true, false)
		if role, ok := e.orgRole(who, org); ok && role != "collaborator" {
			t.Errorf("organization role with a grant left = %q, want collaborator", role)
		}

		// Revoking the last one removes the membership.
		e.revoke(who, sibling)
		want("all revoked", sibling, false, false, false)
		if role, ok := e.orgRole(who, org); ok && role != "" {
			t.Errorf("organization role after the last revoke = %q, want none", role)
		}
		if e.canOrg(who, org, authz.PermOrgList) {
			t.Error("a principal with no grants still lists the organization")
		}
		if set := e.lists(who, authz.PermResourceView); covers(set, res) || covers(set, sibling) {
			t.Errorf("ListResources after revoking everything = %+v", set)
		}

		// Revoking what is not granted is reported.
		if err := cfg.ResourceGranter.RevokeResourceRole(ctx, who, res); !errors.Is(err, authz.ErrGrantNotFound) {
			t.Errorf("revoking a missing grant = %v, want ErrGrantNotFound", err)
		}
	})

	t.Run("members_keep_organization_access", func(t *testing.T) {
		e := &resourceEnv{t: t, ctx: ctx, cfg: cfg}
		org := e.organization()
		res := e.resource(org)
		member, admin := e.principal(), e.principal()
		cfg.GrantOrgRole(t, org, member, "member")
		cfg.GrantOrgRole(t, org, admin, "admin")

		if !e.can(member, authz.PermResourceView, res) || e.can(member, authz.PermResourceEdit, res) {
			t.Error("a member's organization access to a resource is not view without edit")
		}
		if !e.can(admin, authz.PermResourceManage, res) {
			t.Error("an admin cannot manage the organization's resource")
		}
		if set := e.lists(member, authz.PermResourceView); !covers(set, res) {
			t.Errorf("ListResources(view) for a member = %+v, want the organization's resource", set)
		}
		if set := e.lists(member, authz.PermResourceEdit); covers(set, res) {
			t.Errorf("ListResources(edit) for a member = %+v, want none", set)
		}

		// A grant raises a member on one resource, and keeps the
		// membership: revoking it leaves the member a member.
		e.grant(member, res, authz.ResourceRoleMaintainer)
		if !e.can(member, authz.PermResourceManage, res) {
			t.Error("a member granted maintainer cannot manage")
		}
		if role, ok := e.orgRole(member, org); ok && role != "member" {
			t.Errorf("organization role after granting a member = %q, want member", role)
		}
		e.revoke(member, res)
		if e.can(member, authz.PermResourceManage, res) {
			t.Error("a member keeps manage after the grant is revoked")
		}
		if role, ok := e.orgRole(member, org); ok && role != "member" {
			t.Errorf("organization role after revoking a member's grant = %q, want member", role)
		}
	})

	t.Run("grants_are_per_principal_and_organization", func(t *testing.T) {
		e := &resourceEnv{t: t, ctx: ctx, cfg: cfg}
		org := e.organization()
		res := e.resource(org)
		first, second := e.principal(), e.principal()
		e.grant(first, res, authz.ResourceRoleMaintainer)
		if e.can(second, authz.PermResourceView, res) {
			t.Error("a grant to one principal reaches another")
		}
		grants, err := cfg.ResourceGranter.ListResourceGrants(ctx, res)
		if err != nil || len(grants) != 1 {
			t.Errorf("ListResourceGrants = %+v, %v; want one", grants, err)
		}

		// A resource belongs to one organization.
		err = cfg.ResourceGranter.GrantResourceRole(ctx, second, authz.ResourceRef{Type: res.Type, ID: res.ID, OrganizationID: e.organization()}, authz.ResourceRoleViewer, uuid.Nil)
		if !errors.Is(err, authz.ErrResourceOrganizationMismatch) {
			t.Errorf("granting in another organization = %v, want ErrResourceOrganizationMismatch", err)
		}
	})

	t.Run("validation", func(t *testing.T) {
		e := &resourceEnv{t: t, ctx: ctx, cfg: cfg}
		org := e.organization()
		res := e.resource(org)
		who := e.principal()
		g := cfg.ResourceGranter
		for _, role := range []string{"", "admin", "editor", "owner"} {
			if err := g.GrantResourceRole(ctx, who, res, role, uuid.Nil); !errors.Is(err, authz.ErrInvalidResourceRole) {
				t.Errorf("GrantResourceRole(%q) = %v, want ErrInvalidResourceRole", role, err)
			}
		}
		for name, ref := range map[string]authz.ResourceRef{
			"no type":      {ID: res.ID, OrganizationID: org},
			"bad type":     {Type: "project", ID: res.ID, OrganizationID: org},
			"no id":        {Type: ResourceType, OrganizationID: org},
			"bad id":       {Type: ResourceType, ID: "has space", OrganizationID: org},
			"no org":       {Type: ResourceType, ID: res.ID},
			"unregistered": {Type: "nosuchapp_thing", ID: res.ID, OrganizationID: org},
		} {
			err := g.GrantResourceRole(ctx, who, ref, authz.ResourceRoleViewer, uuid.Nil)
			// A provider without a registry may accept a well-formed type of
			// an application it has never heard of.
			if name == "unregistered" && err == nil {
				if err := g.RevokeResourceRole(ctx, who, ref); err != nil {
					t.Errorf("revoking %s: %v", name, err)
				}
				continue
			}
			if !errors.Is(err, authz.ErrInvalidResource) {
				t.Errorf("GrantResourceRole(%s) = %v, want ErrInvalidResource", name, err)
			}
		}
		if _, err := g.ListResources(ctx, who, ResourceType, "delete"); err == nil {
			t.Error("ListResources accepted a permission that is not view, edit or manage")
		}
		if e.can(who, authz.PermResourceView, res) {
			t.Error("a refused grant gave access")
		}
	})
}
