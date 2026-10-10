package managedprincipal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
)

// addVerifiedHuman creates a human whose email is verified.
func addVerifiedHuman(t *testing.T, db *ent.Client, email string) uuid.UUID {
	t.Helper()
	id := addHuman(t, db, email, true)
	if err := db.Human.Update().Where(human.PrincipalID(id)).SetEmailVerifiedAt(time.Now()).Exec(context.Background()); err != nil {
		t.Fatalf("verify email: %v", err)
	}
	return id
}

func TestManagerInvite(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, rec := newService(t, db)
	var changes []accesschange.Change
	svc.accessSink = accesschange.SinkFunc(func(c accesschange.Change) { changes = append(changes, c) })
	family := addVerifiedHuman(t, db, "family@example.com")
	adult := addVerifiedHuman(t, db, "adult@example.com")
	stranger := addVerifiedHuman(t, db, "stranger@example.com")

	// Refusals at issue time.
	for name, in := range map[string]InviteManagerInput{
		"client not allowed": {ClientID: "other", ManagerID: family, Email: "adult@example.com", Role: RoleGuardian},
		"unknown role":       {ClientID: client, ManagerID: family, Email: "adult@example.com", Role: "parent"},
		"no email":           {ClientID: client, ManagerID: family, Role: RoleGuardian},
		"inviter missing":    {ClientID: client, ManagerID: uuid.New(), Email: "adult@example.com", Role: RoleGuardian},
	} {
		if _, err := svc.InviteManager(ctx, in); err == nil {
			t.Errorf("%s: InviteManager succeeded", name)
		}
	}

	inv, err := svc.InviteManager(ctx, InviteManagerInput{ClientID: client, ManagerID: family, Email: "Adult@Example.com", Role: RoleGuardian})
	if err != nil {
		t.Fatalf("InviteManager: %v", err)
	}
	// Nothing changes until the invitee accepts.
	if managed, err := svc.IsManaged(ctx, adult); err != nil || managed {
		t.Fatalf("IsManaged before accept = %v, %v", managed, err)
	}

	// Someone else cannot accept it, nor can a bad token.
	if _, err := svc.AcceptManagerInvite(ctx, inv.Token, stranger); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("accept by another principal = %v, want ErrInvalidInvite", err)
	}
	if _, err := svc.AcceptManagerInvite(ctx, inv.Token, family); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("accept by the inviter = %v, want ErrInvalidInvite", err)
	}
	if _, err := svc.AcceptManagerInvite(ctx, "SFMIAAAAAAAAAAAA", adult); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("accept unknown token = %v, want ErrInvalidInvite", err)
	}

	got, err := svc.AcceptManagerInvite(ctx, inv.Token, adult)
	if err != nil || got != family {
		t.Fatalf("AcceptManagerInvite = %v, %v; want %v", got, err, family)
	}
	if managed, err := svc.IsManaged(ctx, adult); err != nil || !managed {
		t.Errorf("IsManaged after accept = %v, %v; want true", managed, err)
	}
	if roles, err := svc.ManagerRoles(ctx, family, adult); err != nil || len(roles) != 1 || roles[0] != RoleGuardian {
		t.Errorf("ManagerRoles = %v, %v", roles, err)
	}
	p, err := db.Principal.Get(ctx, adult)
	if err != nil || p.Capabilities["can_manage_profile"] || p.Capabilities["can_delegate"] {
		t.Errorf("capabilities after accept = %v, %v", p.Capabilities, err)
	}
	if len(changes) != 1 || changes[0].PrincipalID != adult || changes[0].Reason != accesschange.ManagementGranted {
		t.Errorf("access changes = %+v, want one management_granted for the invitee", changes)
	}
	if got := rec.types(); got[len(got)-1] != EventManagerInviteAccepted {
		t.Errorf("audit = %v", got)
	}

	// Single use.
	if _, err := svc.AcceptManagerInvite(ctx, inv.Token, adult); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("second accept = %v, want ErrInvalidInvite", err)
	}
	// The email is verified, so the guardian can release the adult again.
	if err := svc.Release(ctx, family, adult); err != nil {
		t.Errorf("Release: %v", err)
	}
	if n := len(changes); n != 2 || changes[1].PrincipalID != adult || changes[1].Reason != accesschange.ManagementEnded {
		t.Errorf("access changes after release = %+v, want management_ended for the released principal", changes)
	}
}

func TestManagerInviteRefusals(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, _ := newService(t, db)
	family := addVerifiedHuman(t, db, "family@example.com")
	other := addVerifiedHuman(t, db, "other@example.com")
	unverified := addHuman(t, db, "unverified@example.com", true)
	manager := addVerifiedHuman(t, db, "manager@example.com")
	now := time.Now()
	svc.now = func() time.Time { return now }

	invite := func(email string) *ManagerInvite {
		t.Helper()
		inv, err := svc.InviteManager(ctx, InviteManagerInput{ClientID: client, ManagerID: family, Email: email, Role: RoleEducator})
		if err != nil {
			t.Fatalf("InviteManager(%s): %v", email, err)
		}
		return inv
	}

	// An unverified email does not match.
	if _, err := svc.AcceptManagerInvite(ctx, invite("unverified@example.com").Token, unverified); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("unverified accept = %v, want ErrInvalidInvite", err)
	}

	// Already managed: the invitation is not the way to add a manager.
	if _, err := svc.Create(ctx, CreateInput{ActorID: family, DisplayName: "Kid", ClientID: client, Email: "kid@example.com",
		Managers: []ManagerInput{{family, RoleGuardian}}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	managedKid, err := db.Human.Query().Where(human.EmailEQ("kid@example.com")).Only(ctx)
	if err != nil {
		t.Fatalf("kid: %v", err)
	}
	if err := svc.VerifyEmail(ctx, managedKid.PrincipalID, now); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if _, err := svc.AcceptManagerInvite(ctx, invite("kid@example.com").Token, managedKid.PrincipalID); !errors.Is(err, ErrAlreadyManaged) {
		t.Errorf("accept while managed = %v, want ErrAlreadyManaged", err)
	}

	// A principal that manages others cannot become managed.
	if _, err := svc.Create(ctx, CreateInput{ActorID: manager, DisplayName: "Ward", ClientID: client, Managers: []ManagerInput{{manager, RoleGuardian}}}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.AcceptManagerInvite(ctx, invite("manager@example.com").Token, manager); !errors.Is(err, ErrManagesOthers) {
		t.Errorf("accept while managing = %v, want ErrManagesOthers", err)
	}

	// Revoked and expired invitations.
	revoked := invite("other@example.com")
	if err := svc.RevokeManagerInvite(ctx, other, revoked.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke by another = %v, want ErrNotFound", err)
	}
	if err := svc.RevokeManagerInvite(ctx, family, revoked.ID); err != nil {
		t.Fatalf("RevokeManagerInvite: %v", err)
	}
	if _, err := svc.AcceptManagerInvite(ctx, revoked.Token, other); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("accept revoked = %v, want ErrInvalidInvite", err)
	}
	expiring := invite("other@example.com")
	svc.now = func() time.Time { return now.Add(DefaultInviteTTL + time.Second) }
	if _, err := svc.AcceptManagerInvite(ctx, expiring.Token, other); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("accept expired = %v, want ErrInvalidInvite", err)
	}
}

// TestRemovingTheLastManagerRecordsManagementEnded verifies that releasing a
// principal by removing its last manager records management_ended, and that
// removing one of several managers records nothing.
func TestRemovingTheLastManagerRecordsManagementEnded(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, _ := newService(t, db)
	var changes []accesschange.Change
	svc.accessSink = accesschange.SinkFunc(func(c accesschange.Change) { changes = append(changes, c) })
	parent := addVerifiedHuman(t, db, "parent@example.com")
	teacher := addVerifiedHuman(t, db, "teacher@example.com")
	kid, err := svc.Create(ctx, CreateInput{ActorID: parent, DisplayName: "Kid", ClientID: client, Email: "kid@example.com",
		Managers: []ManagerInput{{parent, RoleGuardian}, {teacher, RoleEducator}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := db.Human.Update().Where(human.PrincipalID(kid)).SetEmailVerifiedAt(time.Now()).Exec(ctx); err != nil {
		t.Fatalf("verify email: %v", err)
	}
	if err := svc.RemoveManager(ctx, kid, ManagerInput{teacher, RoleEducator}, parent); err != nil {
		t.Fatalf("RemoveManager: %v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("access changes after removing one of two managers = %+v, want none", changes)
	}
	if err := svc.RemoveManager(ctx, kid, ManagerInput{parent, RoleGuardian}, parent); err != nil {
		t.Fatalf("RemoveManager last: %v", err)
	}
	if len(changes) != 1 || changes[0].PrincipalID != kid || changes[0].Reason != accesschange.ManagementEnded {
		t.Errorf("access changes = %+v, want one management_ended for the released principal", changes)
	}
}

func TestDeclineManagerInvite(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, rec := newService(t, db)
	var changes []accesschange.Change
	svc.accessSink = accesschange.SinkFunc(func(c accesschange.Change) { changes = append(changes, c) })
	family := addVerifiedHuman(t, db, "family@example.com")
	adult := addVerifiedHuman(t, db, "adult@example.com")
	stranger := addVerifiedHuman(t, db, "stranger@example.com")
	unverified := addHuman(t, db, "unverified@example.com", true)

	invite := func(email string) *ManagerInvite {
		t.Helper()
		inv, err := svc.InviteManager(ctx, InviteManagerInput{ClientID: client, ManagerID: family, Email: email, Role: RoleGuardian})
		if err != nil {
			t.Fatalf("InviteManager(%s): %v", email, err)
		}
		return inv
	}
	inv := invite("adult@example.com")

	// Only the invitee may decline, and a malformed token matches nothing.
	if err := svc.DeclineManagerInvite(ctx, inv.Token, stranger); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("decline by a stranger = %v, want ErrInvalidInvite", err)
	}
	if err := svc.DeclineManagerInvite(ctx, inv.Token, family); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("decline by the inviter = %v, want ErrInvalidInvite", err)
	}
	if err := svc.DeclineManagerInvite(ctx, "SFMIAAAAAAAAAAAA", adult); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("decline of an unknown token = %v, want ErrInvalidInvite", err)
	}
	if err := svc.DeclineManagerInvite(ctx, "x", adult); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("decline of a malformed token = %v, want ErrInvalidInvite", err)
	}
	if err := svc.DeclineManagerInvite(ctx, invite("unverified@example.com").Token, unverified); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("decline with an unverified email = %v, want ErrInvalidInvite", err)
	}
	// A refused decline leaves the invitation acceptable.
	row, err := db.ManagerInvite.Get(ctx, inv.ID)
	if err != nil || row.DeclinedAt != nil {
		t.Fatalf("invitation after refused declines = %+v, %v", row, err)
	}

	if err := svc.DeclineManagerInvite(ctx, inv.Token, adult); err != nil {
		t.Fatalf("DeclineManagerInvite: %v", err)
	}
	row, err = db.ManagerInvite.Get(ctx, inv.ID)
	if err != nil || row.DeclinedAt == nil || row.DeclinedBy == nil || *row.DeclinedBy != adult || row.AcceptedAt != nil {
		t.Errorf("invitation after decline = %+v, %v", row, err)
	}
	if got := rec.types(); got[len(got)-1] != EventManagerInviteDeclined {
		t.Errorf("audit = %v, want the decline event last", got)
	}
	last := rec.events[len(rec.events)-1]
	if last.Details["manager_principal_id"] != family.String() || last.Details["invite_id"] != inv.ID.String() {
		t.Errorf("decline event details = %v, want the inviter and the invitation", last.Details)
	}

	// Single use: neither a second decline nor an acceptance works, and
	// nothing about the invitee changed.
	if err := svc.DeclineManagerInvite(ctx, inv.Token, adult); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("second decline = %v, want ErrInvalidInvite", err)
	}
	if _, err := svc.AcceptManagerInvite(ctx, inv.Token, adult); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("accept after decline = %v, want ErrInvalidInvite", err)
	}
	if managed, err := svc.IsManaged(ctx, adult); err != nil || managed {
		t.Errorf("IsManaged after decline = %v, %v; want false", managed, err)
	}
	if len(changes) != 0 {
		t.Errorf("access changes = %+v, want none", changes)
	}
	// The inviter cannot withdraw a declined invitation.
	if err := svc.RevokeManagerInvite(ctx, family, inv.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke after decline = %v, want ErrNotFound", err)
	}

	// An accepted invitation cannot be declined.
	second := invite("adult@example.com")
	if _, err := svc.AcceptManagerInvite(ctx, second.Token, adult); err != nil {
		t.Fatalf("AcceptManagerInvite: %v", err)
	}
	if err := svc.DeclineManagerInvite(ctx, second.Token, adult); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("decline after accept = %v, want ErrInvalidInvite", err)
	}

	// A revoked or expired invitation cannot be declined.
	other := addVerifiedHuman(t, db, "other@example.com")
	revoked, err := svc.InviteManager(ctx, InviteManagerInput{ClientID: client, ManagerID: family, Email: "other@example.com", Role: RoleEducator})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeManagerInvite(ctx, family, revoked.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeclineManagerInvite(ctx, revoked.Token, other); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("decline after revoke = %v, want ErrInvalidInvite", err)
	}
	expiring, err := svc.InviteManager(ctx, InviteManagerInput{ClientID: client, ManagerID: family, Email: "other@example.com", Role: RoleEducator})
	if err != nil {
		t.Fatal(err)
	}
	svc.now = func() time.Time { return time.Now().Add(DefaultInviteTTL + time.Hour) }
	if err := svc.DeclineManagerInvite(ctx, expiring.Token, other); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("decline after expiry = %v, want ErrInvalidInvite", err)
	}
}
