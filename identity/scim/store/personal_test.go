package store_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/scim"
)

func TestPersonalOrganizationRefusesGroupMembers(t *testing.T) {
	ctx := scim.WithPlatformScope(context.Background())
	s, db := newStoreWithDB(t)
	u := createUser(t, s, "sam@example.com", "Sam")
	org, err := db.Organization.Create().SetName("Sam").SetSlug("sam").SetOrgType(organization.OrgTypePersonal).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = s.AddMemberToGroup(ctx, org.ID.String(), u.ID)
	if got := scimStatus(t, err); got != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", got)
	}
	if n := db.PrincipalMembership.Query().CountX(ctx); n != 0 {
		t.Errorf("memberships = %d, want 0", n)
	}
}
