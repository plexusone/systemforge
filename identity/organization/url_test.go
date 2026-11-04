package organization_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/organization"
)

func TestOrganizationURLsMustBeHTTPS(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	svc := organization.NewService(db)
	str := func(s string) *string { return &s }

	for _, bad := range []string{"javascript:alert(1)", "http://cdn.example.com/a.png", "/logo.png"} {
		_, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, LogoURL: str(bad)})
		if !errors.Is(err, organization.ErrInvalidURL) {
			t.Errorf("Create logo %q: %v, want ErrInvalidURL", bad, err)
		}
	}
	org, err := svc.Create(ctx, organization.CreateOrganizationInput{
		Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam,
		LogoURL: str("https://cdn.example.com/a.png"), WebsiteURL: str("https://acme.example.com"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Update(ctx, org.ID, organization.UpdateOrganizationInput{WebsiteURL: str("javascript:alert(1)")}); !errors.Is(err, organization.ErrInvalidURL) {
		t.Errorf("Update website: %v, want ErrInvalidURL", err)
	}
	if _, err := svc.Update(ctx, org.ID, organization.UpdateOrganizationInput{LogoURL: str("")}); err != nil {
		t.Errorf("Update clearing logo: %v", err)
	}

	// A personal organization's logo is the provider avatar; a bad one is dropped.
	owner := newHuman(t, db, "kim@example.com")
	personal, err := svc.CreatePersonalOrg(ctx, organization.CreatePersonalOrgInput{
		Name: "Kim", Slug: "kim", OwnerPrincipalID: owner, LogoURL: str("http://avatars.example.com/k.png"),
	})
	if err != nil {
		t.Fatalf("CreatePersonalOrg: %v", err)
	}
	if personal.LogoURL != nil {
		t.Errorf("personal logo = %q, want none", *personal.LogoURL)
	}
}
