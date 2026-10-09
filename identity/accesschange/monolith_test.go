package accesschange_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/relyingparty"
)

// TestSharedCacheInTheMonolith verifies the same-process arrangement of
// ADR-010: SystemAuth's services record into the very RevocationCache the
// relying parties read, so a removal is visible on the next request.
func TestSharedCacheInTheMonolith(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	cache := relyingparty.NewRevocationCache()
	orgs := organization.NewService(db, organization.WithAccessChangeSink(accesschange.ToSink(cache)))

	person := func(email string) uuid.UUID {
		p, err := db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier(email).SetDisplayName(email).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	owner, kim := person("owner@example.com"), person("kim@example.com")
	org, err := orgs.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orgs.AddMember(ctx, organization.AddMemberInput{OrganizationID: org.ID, PrincipalID: kim, Role: organization.RoleMember}); err != nil {
		t.Fatal(err)
	}

	issued := time.Now()
	if !cache.Accept(kim.String(), org.ID.String(), issued) {
		t.Fatal("token refused before any change")
	}
	if err := orgs.RemoveMember(ctx, org.ID, kim); err != nil {
		t.Fatal(err)
	}
	if cache.Accept(kim.String(), org.ID.String(), issued) {
		t.Error("a token issued before the removal is still accepted")
	}
	if !cache.Accept(kim.String(), org.ID.String(), time.Now().Add(cache.Margin()+time.Second)) {
		t.Error("a token issued after the margin is refused")
	}
	if !cache.Accept(owner.String(), org.ID.String(), issued) {
		t.Error("the owner was affected by another member's removal")
	}
}
