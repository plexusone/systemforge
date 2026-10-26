package store_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	entorg "github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/scim"
)

// A platform credential's group slug obeys the organization slug rules:
// an externalId must be a valid, available slug, including one outside
// another organization's cooling-off period.
func TestGroupSlugFollowsOrganizationRules(t *testing.T) {
	ctx := scim.WithPlatformScope(context.Background())
	s, db := newStoreWithDB(t)
	releaser := createUser(t, s, "releaser@example.com", "Releaser")

	if _, err := db.SlugReservation.Create().
		SetSlug("acme-old").
		SetReleasedByPrincipalID(uuid.MustParse(releaser.ID)).
		SetReleasedAt(time.Now()).
		SetExpiresAt(time.Now().Add(time.Hour)).
		Save(ctx); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		externalID string
		want       int
	}{
		{"Weird/../Slug With Space", http.StatusBadRequest},
		{"9lives", http.StatusBadRequest},
		{"admin", http.StatusBadRequest},
		{"acme-old", http.StatusConflict},
	} {
		if _, err := s.CreateGroup(ctx, &scim.Group{Resource: scim.Resource{ExternalID: tc.externalID}, DisplayName: "Acme"}); scimStatus(t, err) != tc.want {
			t.Errorf("externalId %q: %v, want %d", tc.externalID, err, tc.want)
		}
	}
	if n := db.Organization.Query().CountX(ctx); n != 0 {
		t.Fatalf("organizations = %d, want 0", n)
	}

	g, err := s.CreateGroup(ctx, &scim.Group{Resource: scim.Resource{ExternalID: "acme"}, DisplayName: "Acme"})
	if err != nil || g.ExternalID != "acme" {
		t.Fatalf("CreateGroup acme = %+v, %v", g, err)
	}
	if _, err := s.CreateGroup(ctx, &scim.Group{Resource: scim.Resource{ExternalID: "acme"}, DisplayName: "Other"}); scimStatus(t, err) != http.StatusConflict {
		t.Errorf("taken externalId: %v", err)
	}
	// Without an externalId the slug is generated, and is unique.
	g2, err := s.CreateGroup(ctx, &scim.Group{DisplayName: "Acme"})
	if err != nil || g2.ExternalID != "acme-1" {
		t.Errorf("generated slug = %+v, %v", g2, err)
	}
}

// Personal organizations belong to their owners: a platform credential can
// neither rename nor delete one.
func TestPersonalOrganizationIsNotManagedAsAGroup(t *testing.T) {
	ctx := scim.WithPlatformScope(context.Background())
	s, db := newStoreWithDB(t)
	org, err := db.Organization.Create().SetName("Sam").SetSlug("sam").SetOrgType(entorg.OrgTypePersonal).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateGroup(ctx, org.ID.String(), &scim.Group{DisplayName: "Renamed"}); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("rename personal: %v", err)
	}
	if err := s.DeleteGroup(ctx, org.ID.String()); scimStatus(t, err) != http.StatusForbidden {
		t.Errorf("delete personal: %v", err)
	}
	got := db.Organization.GetX(ctx, org.ID)
	if got.Name != "Sam" || !got.Active {
		t.Errorf("personal organization changed: %+v", got)
	}
}

// Deleting a group soft-deletes the organization, as the organization
// service does, even when it has members; the error never carries database
// text.
func TestDeleteGroupSoftDeletes(t *testing.T) {
	ctx := scim.WithPlatformScope(context.Background())
	s, db := newStoreWithDB(t)
	g, err := s.CreateGroup(ctx, &scim.Group{DisplayName: "Ops"})
	if err != nil {
		t.Fatal(err)
	}
	u := createUser(t, s, "ops@example.com", "Ops")
	if err := s.AddMemberToGroup(ctx, g.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	org := db.Organization.GetX(ctx, uuid.MustParse(g.ID))
	if org.Active {
		t.Error("organization still active")
	}
	if _, err := s.GetGroupByID(ctx, g.ID); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("deleted group still visible: %v", err)
	}
	groups, total, err := s.ListGroups(ctx, scim.ListOptions{StartIndex: 1, Count: 10})
	if err != nil || total != 0 || len(groups) != 0 {
		t.Errorf("ListGroups after delete = %d (%d), %v", len(groups), total, err)
	}
	if _, err := s.UpdateGroup(ctx, g.ID, &scim.Group{DisplayName: "Back"}); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("rename deleted group: %v", err)
	}
	if err := s.DeleteGroup(ctx, g.ID); scimStatus(t, err) != http.StatusNotFound {
		t.Errorf("delete twice: %v", err)
	}
}

// A database error reaches the client as a generic 500, without its text.
func TestStoreErrorsDoNotCarryDatabaseText(t *testing.T) {
	ctx := scim.WithPlatformScope(context.Background())
	s, db := newStoreWithDB(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.ListUsers(ctx, scim.ListOptions{StartIndex: 1, Count: 10})
	var se *scim.Error
	if !errors.As(err, &se) || se.Status != http.StatusInternalServerError || se.Detail != "internal error" {
		t.Errorf("ListUsers on a closed database = %v", err)
	}
}
