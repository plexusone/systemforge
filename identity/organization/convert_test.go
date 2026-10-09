package organization_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/identity/organization"
)

type countingSyncer struct {
	authz.RelationshipSyncer
	registered []uuid.UUID
}

func (c *countingSyncer) RegisterOrganization(ctx context.Context, orgID, ownerID uuid.UUID) error {
	c.registered = append(c.registered, orgID)
	return nil
}

func TestConvertToTeam(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	syn := &countingSyncer{RelationshipSyncer: noop.NewSyncer()}
	svc := organization.NewService(db, organization.WithAuthzSyncer(syn))
	alice := newHuman(t, db, "alice@example.com")
	collab := newHuman(t, db, "collab@example.com")
	org := personalOrg(t, svc, alice, "alice")
	if _, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: collab, Role: organization.RoleCollaborator}); err != nil {
		t.Fatalf("AddMember collaborator: %v", err)
	}
	syn.registered = nil

	res, err := svc.ConvertToTeam(ctx, org.ID, "alice-co", alice)
	if err != nil {
		t.Fatalf("ConvertToTeam: %v", err)
	}
	if res.Team.ID != org.ID || res.Team.Slug != "alice-co" || res.Team.OrgType != organization.OrgTypeTeam {
		t.Errorf("team = %+v, want same ID, slug alice-co, type team", res.Team)
	}
	if res.Personal.ID == org.ID || res.Personal.Slug != "alice" || res.Personal.OrgType != organization.OrgTypePersonal {
		t.Errorf("personal = %+v, want a new personal organization with the handle", res.Personal)
	}
	if len(syn.registered) != 1 || syn.registered[0] != res.Personal.ID {
		t.Errorf("syncer registered %v, want the new personal organization", syn.registered)
	}

	// Memberships of the converted organization are untouched, and it now
	// accepts members like any team.
	for _, id := range []uuid.UUID{alice, collab} {
		if _, err := svc.GetMembership(ctx, org.ID, id); err != nil {
			t.Errorf("membership of %s lost: %v", id, err)
		}
	}
	if m, err := svc.GetMembership(ctx, org.ID, alice); err != nil || m.Role != organization.RoleOwner {
		t.Errorf("owner membership = %+v, %v", m, err)
	}
	if _, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: newHuman(t, db, "m@example.com"), Role: "member"}); err != nil {
		t.Errorf("AddMember on converted team: %v", err)
	}
	// The new personal organization has exactly its owner.
	if m, err := svc.GetMembership(ctx, res.Personal.ID, alice); err != nil || m.Role != organization.RoleOwner {
		t.Errorf("new personal owner membership = %+v, %v", m, err)
	}
	if p, err := svc.GetPersonalOrg(ctx, alice); err != nil || p.ID != res.Personal.ID {
		t.Errorf("GetPersonalOrg = %+v, %v; want the new one", p, err)
	}
	// The handle reservation was consumed; nothing is left cooling off for it.
	if n := db.SlugReservation.Query().CountX(ctx); n != 0 {
		t.Errorf("%d reservations left, want 0", n)
	}
	// The old handle no longer aliases to the team.
	if got, alias, err := svc.ResolveSlug(ctx, "alice"); err != nil || alias || got.ID != res.Personal.ID {
		t.Errorf("ResolveSlug(handle) = %+v, %v, %v", got, alias, err)
	}
}

func TestConvertToTeamRefusals(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	svc := organization.NewService(db)
	alice := newHuman(t, db, "alice@example.com")
	bob := newHuman(t, db, "bob@example.com")
	org := personalOrg(t, svc, alice, "alice")
	personalOrg(t, svc, bob, "bobby")
	team, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "T", Slug: "tteam", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &alice})
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		org   uuid.UUID
		slug  string
		actor uuid.UUID
		want  error
	}{
		"not the owner":  {org.ID, "fresh", bob, organization.ErrNotOwner},
		"already a team": {team.ID, "fresh", alice, organization.ErrNotPersonal},
		"taken slug":     {org.ID, "bobby", alice, organization.ErrSlugTaken},
		"reserved slug":  {org.ID, "admin", alice, organization.ErrSlugReserved},
		"same slug":      {org.ID, "alice", alice, organization.ErrSlugTaken},
		"unknown org":    {uuid.New(), "fresh", alice, organization.ErrOrganizationNotFound},
	}
	for name, tc := range cases {
		if _, err := svc.ConvertToTeam(ctx, tc.org, tc.slug, tc.actor); !errors.Is(err, tc.want) {
			t.Errorf("%s: ConvertToTeam = %v, want %v", name, err, tc.want)
		}
	}
	// Nothing changed.
	got, err := svc.GetByID(ctx, org.ID)
	if err != nil || got.Slug != "alice" || got.OrgType != organization.OrgTypePersonal {
		t.Errorf("organization after refusals = %+v, %v", got, err)
	}
	if n := db.SlugReservation.Query().CountX(ctx); n != 0 {
		t.Errorf("%d reservations after refused conversions, want 0", n)
	}
}
