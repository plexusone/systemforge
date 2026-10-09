package signup

import (
	"context"
	"errors"
	"net/url"
	"path"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/invite"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/principal"
)

type fixture struct {
	db      *ent.Client
	svc     Service
	orgs    organization.Service
	invites invite.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	orgs := organization.NewService(db)
	invites := invite.NewService(db, "https://app.example.com")
	return &fixture{db: db, orgs: orgs, invites: invites, svc: NewService(db, principal.NewService(db), orgs, invites)}
}

func input(email, slug string) SignupInput {
	return SignupInput{Email: email, DisplayName: "Kim", PersonalOrgSlug: slug}
}

func TestSignup(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	res, err := f.svc.Signup(ctx, input("kim@example.com", "kim"))
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if res.Principal.Identifier != "kim@example.com" || res.PersonalOrganization.Slug != "kim" ||
		res.Membership == nil || res.Membership.Role != organization.RoleOwner {
		t.Fatalf("result = %+v", res)
	}

	if _, err := f.svc.Signup(ctx, input("kim@example.com", "kim2")); !errors.Is(err, ErrEmailTaken) {
		t.Errorf("duplicate email = %v, want ErrEmailTaken", err)
	}
	if _, err := f.svc.Signup(ctx, input("lee@example.com", "kim")); err == nil {
		t.Error("taken slug accepted")
	}
	for name, in := range map[string]SignupInput{
		"no email":   {DisplayName: "X", PersonalOrgSlug: "x"},
		"bad email":  input("not-an-email", "x"),
		"no name":    {Email: "x@example.com", PersonalOrgSlug: "x"},
		"no slug":    {Email: "x@example.com", DisplayName: "X"},
		"managed id": input("human:"+uuid.NewString(), "x"),
	} {
		if _, err := f.svc.Signup(ctx, in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestFailedSignupLeavesNoUser verifies that a signup failing after the
// user is created removes the user, so the email can be used again.
func TestFailedSignupLeavesNoUser(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	// An invalid slug passes the availability check but fails creation.
	if _, err := f.svc.Signup(ctx, input("kim@example.com", "Not A Slug!")); err == nil {
		t.Fatal("signup with an invalid slug succeeded")
	}
	if n, err := f.db.Principal.Query().Count(ctx); err != nil || n != 0 {
		t.Errorf("principals after a failed signup = %d, %v; want 0", n, err)
	}
	if _, err := f.svc.Signup(ctx, input("kim@example.com", "kim")); err != nil {
		t.Errorf("retrying the signup: %v", err)
	}
}

func TestSignupOrGetExisting(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	created, isNew, err := f.svc.SignupOrGetExisting(ctx, SignupInput{Email: "kim@example.com", DisplayName: "Kim", PersonalOrgSlug: "kim"})
	if err != nil || !isNew {
		t.Fatalf("first sign-in = %v, %v", isNew, err)
	}

	// An existing account is returned only for a verified address.
	unverified := SignupInput{Email: "kim@example.com", DisplayName: "Impostor", PersonalOrgSlug: "imp"}
	if _, _, err := f.svc.SignupOrGetExisting(ctx, unverified); !errors.Is(err, ErrEmailNotVerified) {
		t.Errorf("unverified email for an existing account = %v, want ErrEmailNotVerified", err)
	}
	verified := unverified
	verified.EmailVerified = true
	got, isNew, err := f.svc.SignupOrGetExisting(ctx, verified)
	if err != nil || isNew || got.Principal.ID != created.Principal.ID || got.Membership == nil {
		t.Errorf("verified sign-in = %+v, %v, %v", got, isNew, err)
	}
}

func TestSignupWithInvite(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	owner, err := f.svc.Signup(ctx, input("owner@example.com", "owner"))
	if err != nil {
		t.Fatalf("owner signup: %v", err)
	}
	team, err := f.orgs.Create(ctx, organization.CreateOrganizationInput{Name: "Team", Slug: "team", OwnerPrincipalID: &owner.Principal.ID})
	if err != nil {
		t.Fatalf("team: %v", err)
	}
	res, err := f.invites.Create(ctx, invite.CreateInviteInput{OrganizationID: team.ID, InviterPrincipalID: owner.Principal.ID, Email: "New@Example.com", Role: "member"})
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	u, err := url.Parse(res.InviteURL)
	if err != nil {
		t.Fatalf("invite URL: %v", err)
	}
	token := path.Base(u.Path)

	// Someone else holding the link cannot sign up under another address.
	if _, err := f.svc.SignupWithInvite(ctx, AcceptInviteOnSignupInput{SignupInput: input("other@example.com", "other"), InviteToken: token}); !errors.Is(err, ErrInviteEmailMismatch) {
		t.Errorf("signup under another email = %v, want ErrInviteEmailMismatch", err)
	}
	if _, err := f.svc.SignupWithInvite(ctx, AcceptInviteOnSignupInput{SignupInput: input("new@example.com", "newbie"), InviteToken: "bogus"}); err == nil {
		t.Error("signup with a bogus invite token succeeded")
	}

	joined, err := f.svc.SignupWithInvite(ctx, AcceptInviteOnSignupInput{SignupInput: input("new@example.com", "newbie"), InviteToken: token})
	if err != nil {
		t.Fatalf("SignupWithInvite: %v", err)
	}
	if joined.InvitedOrganizationID != team.ID {
		t.Errorf("invited organization = %v", joined.InvitedOrganizationID)
	}
	if m, err := f.orgs.GetMembership(ctx, team.ID, joined.Principal.ID); err != nil || m.Role != "member" {
		t.Errorf("team membership = %+v, %v", m, err)
	}
}
