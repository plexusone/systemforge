package organization_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/slugreservation"
	"github.com/plexusone/systemforge/identity/organization"

	_ "github.com/mattn/go-sqlite3"
)

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

func personalOrg(t *testing.T, svc organization.Service, owner uuid.UUID, slug string) *organization.Organization {
	t.Helper()
	org, err := svc.CreatePersonalOrg(context.Background(), organization.CreatePersonalOrgInput{OwnerPrincipalID: owner, Name: slug, Slug: slug})
	if err != nil {
		t.Fatalf("CreatePersonalOrg(%s): %v", slug, err)
	}
	return org
}

func TestRenameReservesOldSlugAndAliases(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	svc := organization.NewService(db)
	alice := newHuman(t, db, "alice@example.com")
	bob := newHuman(t, db, "bob@example.com")
	org := personalOrg(t, svc, alice, "alice")

	if err := svc.Rename(ctx, org.ID, "alice-new", alice); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	got, alias, err := svc.ResolveSlug(ctx, "alice-new")
	if err != nil || alias || got.ID != org.ID {
		t.Fatalf("ResolveSlug(new) = %v, %v, %v", got, alias, err)
	}
	got, alias, err = svc.ResolveSlug(ctx, "alice")
	if err != nil || !alias || got.ID != org.ID || got.Slug != "alice-new" {
		t.Fatalf("ResolveSlug(old) = %+v, %v, %v; want alias of the renamed organization", got, alias, err)
	}
	// GetBySlug keeps exact-match semantics.
	if _, err := svc.GetBySlug(ctx, "alice"); err == nil {
		t.Error("GetBySlug(old) found the organization; want exact match only")
	}

	ok, err := svc.SlugAvailable(ctx, "alice")
	if ok || !errors.Is(err, organization.ErrSlugCoolingOff) {
		t.Errorf("SlugAvailable(held) = %v, %v; want false, ErrSlugCoolingOff", ok, err)
	}
	// Someone else cannot take it.
	_, err = svc.Create(ctx, organization.CreateOrganizationInput{Name: "A", Slug: "alice", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &bob})
	if !errors.Is(err, organization.ErrSlugCoolingOff) {
		t.Errorf("Create by another principal = %v, want ErrSlugCoolingOff", err)
	}
	// The releasing principal can, which spends the reservation.
	if _, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Alice Co", Slug: "alice", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &alice}); err != nil {
		t.Fatalf("Create by releasing principal: %v", err)
	}
	got, alias, err = svc.ResolveSlug(ctx, "alice")
	if err != nil || alias || got.Slug != "alice" || got.ID == org.ID {
		t.Errorf("ResolveSlug after reclaim = %+v, %v, %v; want the new organization, not an alias", got, alias, err)
	}
}

func TestRenameRules(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	svc := organization.NewService(db)
	alice := newHuman(t, db, "alice@example.com")
	bob := newHuman(t, db, "bob@example.com")
	org := personalOrg(t, svc, alice, "alice")
	personalOrg(t, svc, bob, "bobby")

	for name, tc := range map[string]struct {
		slug  string
		actor uuid.UUID
		want  error
	}{
		"not owner": {"fresh", bob, organization.ErrNotOwner},
		"taken":     {"bobby", alice, organization.ErrSlugTaken},
		"reserved":  {"admin", alice, organization.ErrSlugReserved},
		"invalid":   {"Bad Slug", alice, organization.ErrInvalidSlug},
		"same":      {"alice", alice, organization.ErrSlugTaken},
	} {
		if err := svc.Rename(ctx, org.ID, tc.slug, tc.actor); !errors.Is(err, tc.want) {
			t.Errorf("%s: Rename = %v, want %v", name, err, tc.want)
		}
	}
	if n := db.SlugReservation.Query().CountX(ctx); n != 0 {
		t.Errorf("%d reservations after refused renames, want 0", n)
	}
}

func TestReservationExpires(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	svc := organization.NewService(db)
	alice := newHuman(t, db, "alice@example.com")
	bob := newHuman(t, db, "bob@example.com")
	org := personalOrg(t, svc, alice, "alice")
	if err := svc.Rename(ctx, org.ID, "alice-new", alice); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := db.SlugReservation.Update().Where(slugreservation.SlugEQ("alice")).SetExpiresAt(time.Now().Add(-time.Minute)).Save(ctx); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if _, _, err := svc.ResolveSlug(ctx, "alice"); !errors.Is(err, organization.ErrOrganizationNotFound) {
		t.Errorf("ResolveSlug(expired) = %v, want not found", err)
	}
	if n := db.SlugReservation.Query().CountX(ctx); n != 0 {
		t.Errorf("expired reservation not deleted on read: %d rows", n)
	}
	// Anyone may take it now.
	if _, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "A", Slug: "alice", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &bob}); err != nil {
		t.Errorf("Create after expiry: %v", err)
	}
}

func TestOwnerOfReleasingOrganizationMayReclaim(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	svc := organization.NewService(db, organization.WithSlugCoolingOff(time.Hour))
	alice := newHuman(t, db, "alice@example.com")
	team, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "T", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &alice})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// alice releases "acme" via the team; a co-owner can take it back.
	co := newHuman(t, db, "co@example.com")
	if _, err := svc.AddMember(ctx, organization.AddMemberInput{OrganizationID: team.ID, PrincipalID: co, Role: organization.RoleOwner}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := svc.Rename(ctx, team.ID, "acme-inc", alice); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "A", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &co}); err != nil {
		t.Errorf("co-owner of the releasing organization could not reclaim: %v", err)
	}
}
