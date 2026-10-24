package invite_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/invite"
	"github.com/plexusone/systemforge/identity/organization"
)

// inviterFixture is an organization with an owner and an admin, and an
// invite service.
type inviterFixture struct {
	db           *ent.Client
	orgs         organization.Service
	svc          invite.Service
	orgID, owner uuid.UUID
	admin        uuid.UUID
}

func newInviterFixture(t *testing.T, opts ...func(organization.Service) invite.ServiceOption) (*inviterFixture, func() uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	db := openInviteDB(t)
	orgs := organization.NewService(db)
	orgID, owner := seedInviteOrg(t, db)
	admin := newHuman(t, db)
	if _, err := orgs.AddMember(ctx, organization.AddMemberInput{OrganizationID: orgID, PrincipalID: admin, Role: organization.RoleAdmin}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	var svcOpts []invite.ServiceOption
	for _, o := range opts {
		svcOpts = append(svcOpts, o(orgs))
	}
	f := &inviterFixture{db: db, orgs: orgs, svc: invite.NewService(db, "https://app.example.com", svcOpts...), orgID: orgID, owner: owner, admin: admin}
	// demote sets the admin's role to member without going through the
	// organization service, so its pending invites stay pending.
	demote := func() uuid.UUID {
		if err := db.PrincipalMembership.Update().
			Where(principalmembership.OrganizationID(orgID), principalmembership.PrincipalID(admin)).
			SetRole(organization.RoleMember).
			Exec(ctx); err != nil {
			t.Fatalf("demote: %v", err)
		}
		return newHuman(t, db)
	}
	return f, demote
}

func (f *inviterFixture) invite(t *testing.T, inviter uuid.UUID, role string) *invite.InviteResult {
	t.Helper()
	res, err := f.svc.Create(context.Background(), invite.CreateInviteInput{OrganizationID: f.orgID, InviterPrincipalID: inviter, Email: uuid.NewString() + "@example.com", Role: role})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return res
}

// TestAcceptRequiresInviterAuthority verifies that an invitation carries
// its inviter's current authority: once the inviter may no longer invite,
// the invite cannot be accepted, even if it is still pending.
func TestAcceptRequiresInviterAuthority(t *testing.T) {
	ctx := context.Background()
	f, demote := newInviterFixture(t)
	res := f.invite(t, f.admin, organization.RoleAdmin)
	who := demote()
	if _, err := f.svc.Accept(ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: who}); !errors.Is(err, invite.ErrInviterNotAuthorized) {
		t.Fatalf("Accept of a demoted inviter's invite: err = %v, want ErrInviterNotAuthorized", err)
	}
	if _, err := f.orgs.GetMembership(ctx, f.orgID, who); !errors.Is(err, organization.ErrMembershipNotFound) {
		t.Errorf("invitee membership: err = %v, want not found", err)
	}
}

// TestAcceptOwnerInviteRequiresOwnerInviter verifies that an owner invite
// needs an inviter who is still an owner.
func TestAcceptOwnerInviteRequiresOwnerInviter(t *testing.T) {
	ctx := context.Background()
	f, _ := newInviterFixture(t)
	// The admin cannot send an owner invite through the API; one written
	// directly still needs owner authority at acceptance.
	res := f.invite(t, f.admin, organization.RoleOwner)
	if _, err := f.svc.Accept(ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: newHuman(t, f.db)}); !errors.Is(err, invite.ErrInviterNotAuthorized) {
		t.Fatalf("Accept of an admin's owner invite: err = %v, want ErrInviterNotAuthorized", err)
	}
}

// TestRemovingInviterRevokesItsInvites verifies that removing, deactivating
// or demoting a member revokes the pending invitations it may no longer
// send.
func TestRemovingInviterRevokesItsInvites(t *testing.T) {
	ctx := context.Background()
	f, _ := newInviterFixture(t)

	status := func(res *invite.InviteResult) invite.Status {
		t.Helper()
		got, err := f.svc.GetByID(ctx, res.Invite.ID)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		return got.Status
	}

	byAdmin := f.invite(t, f.admin, organization.RoleMember)
	byOwner := f.invite(t, f.owner, organization.RoleMember)
	if err := f.orgs.RemoveMember(ctx, f.orgID, f.admin); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if got := status(byAdmin); got != invite.StatusRevoked {
		t.Errorf("removed admin's invite status = %s, want revoked", got)
	}
	if got := status(byOwner); got != invite.StatusPending {
		t.Errorf("owner's invite status = %s, want pending", got)
	}

	// Demoting the owner to admin revokes its owner invites only.
	m, err := f.orgs.GetMembership(ctx, f.orgID, f.owner)
	if err != nil {
		t.Fatalf("GetMembership: %v", err)
	}
	ownerInvite := f.invite(t, f.owner, organization.RoleOwner)
	admin := organization.RoleAdmin
	if _, err := f.orgs.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Role: &admin}); err != nil {
		t.Fatalf("UpdateMember: %v", err)
	}
	if got := status(ownerInvite); got != invite.StatusRevoked {
		t.Errorf("demoted owner's owner invite status = %s, want revoked", got)
	}
	if got := status(byOwner); got != invite.StatusPending {
		t.Errorf("demoted owner's member invite status = %s, want pending", got)
	}

	// Deactivating revokes the rest.
	inactive := false
	if _, err := f.orgs.UpdateMember(ctx, m.ID, organization.UpdateMemberInput{Active: &inactive}); err != nil {
		t.Fatalf("UpdateMember: %v", err)
	}
	if got := status(byOwner); got != invite.StatusRevoked {
		t.Errorf("deactivated member's invite status = %s, want revoked", got)
	}
}

// TestAcceptAsksAuthorizerForInviter verifies that WithAuthorizer decides
// the inviter's authority instead of its membership.
func TestAcceptAsksAuthorizerForInviter(t *testing.T) {
	ctx := context.Background()
	var platformAdmin uuid.UUID
	f, _ := newInviterFixture(t, func(orgs organization.Service) invite.ServiceOption {
		return invite.WithAuthorizer(rbac.New(
			rbac.WithRoleGetter(organization.MembershipRoleGetter(orgs)),
			rbac.WithPlatformAdminChecker(func(_ context.Context, id uuid.UUID) (bool, error) { return id == platformAdmin, nil }),
		))
	})
	// A platform administrator, who is no member, invites.
	platformAdmin = newHuman(t, f.db)
	res := f.invite(t, platformAdmin, organization.RoleMember)
	if _, err := f.svc.Accept(ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: newHuman(t, f.db)}); err != nil {
		t.Fatalf("Accept of a platform administrator's invite: %v", err)
	}
	// Once no longer a platform administrator, its invites are refused.
	res = f.invite(t, platformAdmin, organization.RoleMember)
	platformAdmin = uuid.Nil
	if _, err := f.svc.Accept(ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: newHuman(t, f.db)}); !errors.Is(err, invite.ErrInviterNotAuthorized) {
		t.Fatalf("Accept after losing platform administration: err = %v, want ErrInviterNotAuthorized", err)
	}
}
