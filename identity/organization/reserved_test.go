package organization_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/organization"

	_ "github.com/mattn/go-sqlite3"
)

func TestReservedSlugs(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	svc := organization.NewService(db, organization.WithReservedSlugs("Notes", "boards"))

	for _, slug := range []string{"admin", "api", "login", "oauth", "well-known", "notes", "boards", "O"} {
		ok, err := svc.SlugAvailable(ctx, slug)
		if ok || !errors.Is(err, organization.ErrSlugReserved) {
			t.Errorf("SlugAvailable(%q) = %v, %v; want false, ErrSlugReserved", slug, ok, err)
		}
	}
	if ok, err := svc.SlugAvailable(ctx, "acme"); err != nil || !ok {
		t.Errorf("SlugAvailable(acme) = %v, %v", ok, err)
	}

	_, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Admin", Slug: "admin", OrgType: organization.OrgTypeTeam})
	if !errors.Is(err, organization.ErrSlugReserved) {
		t.Errorf("Create(admin) = %v, want ErrSlugReserved", err)
	}

	// A generated slug steps past a reserved base.
	got, err := svc.GenerateSlug(ctx, "Notes")
	if err != nil || got != "notes-1" {
		t.Errorf("GenerateSlug(Notes) = %q, %v; want notes-1", got, err)
	}

	if !organization.IsReservedSlug("admin") || organization.IsReservedSlug("acme") {
		t.Error("IsReservedSlug mismatch")
	}
}
