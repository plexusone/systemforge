package invite_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/invite"
	"github.com/plexusone/systemforge/identity/organization"
)

func TestPersonalOrganizationRefusesInvites(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	svc := invite.NewService(db, "https://app.example.com")
	_, owner := seedInviteOrg(t, db)
	personal, err := organization.NewService(db).Create(ctx, organization.CreateOrganizationInput{Name: "Me", Slug: "me-" + uuid.NewString()[:8], OrgType: organization.OrgTypePersonal, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatalf("personal organization: %v", err)
	}

	_, err = svc.Create(ctx, invite.CreateInviteInput{OrganizationID: personal.ID, InviterPrincipalID: owner, Email: "kim@example.com", Role: "member"})
	if !errors.Is(err, organization.ErrPersonalOrganization) {
		t.Errorf("invite as member = %v, want ErrPersonalOrganization", err)
	}
	if _, err := svc.Create(ctx, invite.CreateInviteInput{OrganizationID: personal.ID, InviterPrincipalID: owner, Email: "kim@example.com", Role: organization.RoleCollaborator}); err != nil {
		t.Errorf("invite as collaborator: %v", err)
	}
}
