package managedprincipal

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent/credential"
	"github.com/plexusone/systemforge/identity/ent/human"
)

func TestDelete(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, rec := newService(t, db)
	var changes []accesschange.Change
	svc.accessSink = accesschange.SinkFunc(func(c accesschange.Change) { changes = append(changes, c) })
	guardian := addHuman(t, db, "guardian@example.com", true)
	teacher := addHuman(t, db, "teacher@example.com", true)
	kid, err := svc.Create(ctx, CreateInput{ActorID: guardian, DisplayName: "Robin", ClientID: client, Email: "robin@example.com",
		Managers: []ManagerInput{{guardian, RoleGuardian}, {teacher, RoleEducator}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := db.Human.Update().Where(human.PrincipalID(kid)).SetGivenName("Robin").SetFamilyName("Smith").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IssueLoginToken(ctx, IssueLoginTokenInput{ManagedID: kid, ClientID: client, IssuedBy: teacher}); err != nil {
		t.Fatalf("IssueLoginToken: %v", err)
	}
	if _, err := svc.IssueClaim(ctx, guardian, kid); err != nil {
		t.Fatalf("IssueClaim: %v", err)
	}
	inv, err := svc.InviteManager(ctx, InviteManagerInput{ClientID: client, ManagerID: guardian, Email: "robin@example.com", Role: RoleGuardian})
	if err != nil {
		t.Fatalf("InviteManager: %v", err)
	}

	// An educator cannot delete; neither can a stranger.
	if err := svc.Delete(ctx, teacher, kid); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Delete by an educator = %v, want ErrForbidden", err)
	}
	if err := svc.Delete(ctx, uuid.New(), kid); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Delete by a stranger = %v, want ErrForbidden", err)
	}
	if err := svc.Delete(ctx, guardian, guardian); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("Delete of an unmanaged principal = %v, want ErrNotManaged", err)
	}

	if err := svc.Delete(ctx, guardian, kid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	p, err := db.Principal.Get(ctx, kid)
	if err != nil || p.Active || p.Identifier != "deleted:"+kid.String() || p.DisplayName != deletedDisplayName {
		t.Errorf("principal after delete = %+v, %v", p, err)
	}
	h, err := db.Human.Query().Where(human.PrincipalID(kid)).Only(ctx)
	if err != nil || h.Email != nil || h.EmailVerifiedAt != nil || h.GivenName != "" || h.FamilyName != "" {
		t.Errorf("human after delete = %+v, %v", h, err)
	}
	if n, err := db.Credential.Query().Where(credential.PrincipalID(kid)).Count(ctx); err != nil || n != 0 {
		t.Errorf("credentials after delete = %d, %v", n, err)
	}
	if n, err := db.ManagerClaim.Query().Count(ctx); err != nil || n != 0 {
		t.Errorf("claims after delete = %d, %v", n, err)
	}
	if rels, err := svc.ListManagers(ctx, kid); err != nil || len(rels) != 0 {
		t.Errorf("managers after delete = %+v, %v", rels, err)
	}
	if managed, err := svc.IsManaged(ctx, kid); err != nil || managed {
		t.Errorf("IsManaged after delete = %v, %v", managed, err)
	}
	// The freed address cannot be accepted for.
	if _, err := svc.AcceptManagerInvite(ctx, inv.Token, kid); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("accept after delete = %v, want ErrInvalidInvite", err)
	}
	if len(changes) != 1 || changes[0].PrincipalID != kid || changes[0].Reason != accesschange.Deactivated {
		t.Errorf("access changes = %+v, want one deactivation", changes)
	}
	if got := rec.types(); got[len(got)-1] != EventDeleted {
		t.Errorf("audit = %v, want a final %s", got, EventDeleted)
	}
	// The address is free again, and a second delete finds nothing.
	if _, err := svc.Create(ctx, CreateInput{ActorID: guardian, DisplayName: "Robin", ClientID: client, Email: "robin@example.com",
		Managers: []ManagerInput{{guardian, RoleGuardian}}}); err != nil {
		t.Errorf("Create with the freed address: %v", err)
	}
	if err := svc.Delete(ctx, guardian, kid); !errors.Is(err, ErrNotManaged) {
		t.Errorf("second Delete = %v, want ErrNotManaged", err)
	}
}
