package invite_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path"
	"testing"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/invite"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/internal/pgtest"
	"github.com/plexusone/systemforge/internal/syncrec"
)

func tokenOf(t *testing.T, r *invite.InviteResult) string {
	t.Helper()
	u, err := url.Parse(r.InviteURL)
	if err != nil {
		t.Fatalf("invite URL: %v", err)
	}
	return path.Base(u.Path)
}

func seedInviteOrg(t *testing.T, db *ent.Client) (orgID, inviter uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	p, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("Admin").Save(ctx)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	org, err := organization.NewService(db).Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme-" + uuid.NewString()[:8], OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &p.ID})
	if err != nil {
		t.Fatalf("organization: %v", err)
	}
	return org.ID, p.ID
}

// TestInviteTokensAreHashed verifies that the invite link's token is never
// stored, still finds the invite, and stops working when resent.
func TestInviteTokensAreHashed(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	svc := invite.NewService(db, "https://app.example.com")
	orgID, inviter := seedInviteOrg(t, db)

	res, err := svc.Create(ctx, invite.CreateInviteInput{OrganizationID: orgID, InviterPrincipalID: inviter, Email: "kim@example.com", Role: "member"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	token := tokenOf(t, res)
	row, err := db.Invite.Get(ctx, res.Invite.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	sum := sha256.Sum256([]byte(token))
	if row.Token == token || row.Token != hex.EncodeToString(sum[:]) {
		t.Errorf("stored token %q is not the hash of the link token", row.Token)
	}
	if inv, err := svc.GetByToken(ctx, token); err != nil || inv.ID != res.Invite.ID {
		t.Errorf("GetByToken = %+v, %v", inv, err)
	}
	if _, err := svc.GetByToken(ctx, row.Token); err == nil {
		t.Error("the stored hash works as a token")
	}

	resent, err := svc.Resend(ctx, res.Invite.ID)
	if err != nil {
		t.Fatalf("Resend: %v", err)
	}
	if _, err := svc.GetByToken(ctx, token); err == nil {
		t.Error("the old token works after a resend")
	}
	if _, err := svc.Decline(ctx, tokenOf(t, resent)); err != nil {
		t.Errorf("Decline with the new token: %v", err)
	}
}

// TestHashInviteTokensMigration runs migrations/0003 on PostgreSQL against
// a token stored in plain text by an earlier version.
func TestHashInviteTokensMigration(t *testing.T) {
	ctx := context.Background()
	sqlDB := pgtest.Open(t)
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sqlDB)))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	orgID, inviter := seedInviteOrg(t, db)
	svc := invite.NewService(db, "https://app.example.com")

	// An invite created by this version, and one stored the old way.
	current, err := svc.Create(ctx, invite.CreateInviteInput{OrganizationID: orgID, InviterPrincipalID: inviter, Email: "new@example.com", Role: "member"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	legacy, err := svc.Create(ctx, invite.CreateInviteInput{OrganizationID: orgID, InviterPrincipalID: inviter, Email: "old@example.com", Role: "member"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	const plain = "bGVnYWN5LXRva2VuLXN0b3JlZC1pbi1wbGFpbi10ZXh0IQ=="
	if err := db.Invite.UpdateOneID(legacy.Invite.ID).SetToken(plain).Exec(ctx); err != nil {
		t.Fatalf("store legacy token: %v", err)
	}

	script, err := os.ReadFile("../../migrations/0003_hash_invite_tokens.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	for range 2 { // idempotent
		if _, err := sqlDB.ExecContext(ctx, string(script)); err != nil {
			t.Fatalf("run migration: %v", err)
		}
	}
	if inv, err := svc.GetByToken(ctx, plain); err != nil || inv.ID != legacy.Invite.ID {
		t.Errorf("legacy link after migration = %+v, %v", inv, err)
	}
	if inv, err := svc.GetByToken(ctx, tokenOf(t, current)); err != nil || inv.ID != current.Invite.ID {
		t.Errorf("current link after migration = %+v, %v", inv, err)
	}
}

// TestAcceptSyncsMembershipToAuthz verifies that accepting an invite
// registers the new membership with the authorization syncer, and that a
// sync failure does not undo the acceptance in the default eventual mode.
func TestAcceptSyncsMembershipToAuthz(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	rec := syncrec.New()
	svc := invite.NewService(db, "https://app.example.com", invite.WithAuthzSyncer(rec))
	orgID, inviter := seedInviteOrg(t, db)
	member, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("Member").Save(ctx)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}

	res, err := svc.Create(ctx, invite.CreateInviteInput{OrganizationID: orgID, InviterPrincipalID: inviter, Email: "kim@example.com", Role: "member"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Accept(ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: member.ID}); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	want := "AddOrgMembership:" + member.ID.String() + ":" + orgID.String() + ":member"
	if calls := rec.Calls(); len(calls) != 1 || calls[0] != want {
		t.Errorf("syncer calls = %v, want [%s]", calls, want)
	}

	// Eventual mode (the default) tolerates a sync failure.
	rec.Err = errors.New("authz down")
	other, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("Other").Save(ctx)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	res, err = svc.Create(ctx, invite.CreateInviteInput{OrganizationID: orgID, InviterPrincipalID: inviter, Email: "lee@example.com", Role: "member"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Accept(ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: other.ID}); err != nil {
		t.Errorf("Accept in eventual mode: %v", err)
	}
}
