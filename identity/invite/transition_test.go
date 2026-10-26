package invite_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entinvite "github.com/plexusone/systemforge/identity/ent/invite"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/invite"
)

func openInviteDB(t *testing.T) *ent.Client {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return db
}

func newHuman(t *testing.T, db *ent.Client) uuid.UUID {
	t.Helper()
	p, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("Someone").Save(context.Background())
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	return p.ID
}

// TestAcceptLosesToConcurrentRevoke verifies that an invite revoked while
// it is being accepted is not accepted: the acceptance is a conditional
// update, and the membership written with it is rolled back.
func TestAcceptLosesToConcurrentRevoke(t *testing.T) {
	ctx := context.Background()
	db := openInviteDB(t)
	svc := invite.NewService(db, "https://app.example.com")
	orgID, inviter := seedInviteOrg(t, db)
	who := newHuman(t, db)

	res, err := svc.Create(ctx, invite.CreateInviteInput{OrganizationID: orgID, InviterPrincipalID: inviter, Email: "kim@example.com", Role: "member"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A revoke lands between Accept's read of the invite and its status
	// update: the hook runs it in Accept's transaction, right after the
	// membership is written.
	db.PrincipalMembership.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			v, err := next.Mutate(ctx, m)
			if err != nil {
				return v, err
			}
			pm, ok := m.(*ent.PrincipalMembershipMutation)
			if !ok || !pm.Op().Is(ent.OpCreate) {
				return v, nil
			}
			if err := pm.Client().Invite.Update().
				Where(entinvite.ID(res.Invite.ID)).
				SetStatus(entinvite.StatusRevoked).
				Exec(ctx); err != nil {
				return nil, err
			}
			return v, nil
		})
	})

	if _, err := svc.Accept(ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: who}); !errors.Is(err, invite.ErrNotPending) {
		t.Fatalf("Accept after a concurrent revoke: err = %v, want ErrNotPending", err)
	}
	joined, err := db.PrincipalMembership.Query().Where(principalmembership.OrganizationID(orgID), principalmembership.PrincipalID(who)).Exist(ctx)
	if err != nil {
		t.Fatalf("membership: %v", err)
	}
	if joined {
		t.Error("a revoked invite created a membership")
	}
}

// TestTransitionsOnlyFromPending verifies that revoke, decline and resend
// act only on a pending invite, so they never overwrite an acceptance.
func TestTransitionsOnlyFromPending(t *testing.T) {
	ctx := context.Background()
	db := openInviteDB(t)
	svc := invite.NewService(db, "https://app.example.com")
	orgID, inviter := seedInviteOrg(t, db)
	who := newHuman(t, db)

	res, err := svc.Create(ctx, invite.CreateInviteInput{OrganizationID: orgID, InviterPrincipalID: inviter, Email: "kim@example.com", Role: "member"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Accept(ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: who}); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if err := svc.Revoke(ctx, res.Invite.ID); !errors.Is(err, invite.ErrNotPending) {
		t.Errorf("Revoke of an accepted invite: err = %v, want ErrNotPending", err)
	}
	if _, err := svc.Decline(ctx, tokenOf(t, res)); !errors.Is(err, invite.ErrNotPending) {
		t.Errorf("Decline of an accepted invite: err = %v, want ErrNotPending", err)
	}
	if _, err := svc.Resend(ctx, res.Invite.ID); err == nil {
		t.Error("Resend of an accepted invite succeeded")
	}
	got, err := svc.GetByID(ctx, res.Invite.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != invite.StatusAccepted {
		t.Errorf("status = %s, want accepted", got.Status)
	}
	if err := svc.Revoke(ctx, uuid.New()); err == nil || errors.Is(err, invite.ErrNotPending) {
		t.Errorf("Revoke of an unknown invite: err = %v, want not found", err)
	}
}
