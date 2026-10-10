package managedprincipal

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz/rbac"
)

// TestMutationsGoThroughTheAuthorizer verifies that Create, AddManager and
// RemoveManager check the acting principal (RMI-SYSTEMFORGE-152).
func TestMutationsGoThroughTheAuthorizer(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	admin := uuid.New()
	var svc *Service
	svc = NewService(db, gate{client: true}, WithAuthorizer(rbac.New(
		rbac.WithManagerRoleGetter(func(ctx context.Context, managerID, managedID uuid.UUID) ([]string, error) {
			return svc.ManagerRoles(ctx, managerID, managedID)
		}),
		rbac.WithPlatformAdminChecker(func(_ context.Context, id uuid.UUID) (bool, error) { return id == admin, nil }),
	)))
	guardian := addHuman(t, db, "guardian@example.com", true)
	teacher := addHuman(t, db, "teacher@example.com", true)
	outsider := addHuman(t, db, "outsider@example.com", true)
	newcomer := addHuman(t, db, "newcomer@example.com", true)

	// Create: the actor must be one of the managers, or a platform admin.
	managers := []ManagerInput{{guardian, RoleGuardian}, {teacher, RoleEducator}}
	if _, err := svc.Create(ctx, CreateInput{DisplayName: "Kid", ClientID: client, Managers: managers}); !errors.Is(err, ErrForbidden) {
		t.Errorf("Create without an actor = %v, want ErrForbidden", err)
	}
	if _, err := svc.Create(ctx, CreateInput{DisplayName: "Kid", ClientID: client, Managers: managers, ActorID: outsider}); !errors.Is(err, ErrForbidden) {
		t.Errorf("Create by an outsider = %v, want ErrForbidden", err)
	}
	if n, err := db.Principal.Query().Count(ctx); err != nil || n != 4 {
		t.Fatalf("principals after refused creates = %d, %v; want 4", n, err)
	}
	if _, err := svc.Create(ctx, CreateInput{DisplayName: "Kid", ClientID: client, Managers: managers, ActorID: admin}); err != nil {
		t.Errorf("Create by a platform admin: %v", err)
	}
	kid, err := svc.Create(ctx, CreateInput{DisplayName: "Kid", ClientID: client, Managers: managers, ActorID: teacher})
	if err != nil {
		t.Fatalf("Create by a manager: %v", err)
	}

	// AddManager and RemoveManager need manage_managers: guardians only.
	for name, actor := range map[string]uuid.UUID{"educator": teacher, "outsider": outsider} {
		if err := svc.AddManager(ctx, kid, ManagerInput{newcomer, RoleEducator}, actor); !errors.Is(err, ErrForbidden) {
			t.Errorf("AddManager by %s = %v, want ErrForbidden", name, err)
		}
		if err := svc.RemoveManager(ctx, kid, ManagerInput{teacher, RoleEducator}, actor); !errors.Is(err, ErrForbidden) {
			t.Errorf("RemoveManager by %s = %v, want ErrForbidden", name, err)
		}
	}
	if rels, err := svc.ListManagers(ctx, kid); err != nil || len(rels) != 2 {
		t.Errorf("managers after refused changes = %+v, %v; want 2", rels, err)
	}
	if err := svc.AddManager(ctx, kid, ManagerInput{newcomer, RoleEducator}, guardian); err != nil {
		t.Errorf("AddManager by a guardian: %v", err)
	}
	if err := svc.RemoveManager(ctx, kid, ManagerInput{newcomer, RoleEducator}, guardian); err != nil {
		t.Errorf("RemoveManager by a guardian: %v", err)
	}
}

// TestRedeemClaimNeedsTheIssuersAuthority verifies that a claim stops
// working once its issuer no longer holds manage_credentials.
func TestRedeemClaimNeedsTheIssuersAuthority(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, _ := newService(t, db)
	guardian := addHuman(t, db, "guardian@example.com", true)
	teacher := addHuman(t, db, "teacher@example.com", true)
	parent := addHuman(t, db, "parent@example.com", true)
	kid, err := svc.Create(ctx, CreateInput{ActorID: guardian, DisplayName: "Kid", ClientID: client,
		Managers: []ManagerInput{{guardian, RoleGuardian}, {teacher, RoleEducator}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	claim, err := svc.IssueClaim(ctx, teacher, kid)
	if err != nil {
		t.Fatalf("IssueClaim: %v", err)
	}
	if err := svc.RemoveManager(ctx, kid, ManagerInput{teacher, RoleEducator}, guardian); err != nil {
		t.Fatalf("RemoveManager: %v", err)
	}
	if _, err := svc.RedeemClaim(ctx, claim.Code, parent); !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("RedeemClaim after the issuer left = %v, want ErrInvalidClaim", err)
	}
	if managed, err := svc.ManagerRoles(ctx, parent, kid); err != nil || len(managed) != 0 {
		t.Errorf("roles after refused redeem = %v, %v", managed, err)
	}
	fresh, err := svc.IssueClaim(ctx, guardian, kid)
	if err != nil {
		t.Fatalf("IssueClaim: %v", err)
	}
	if _, err := svc.RedeemClaim(ctx, fresh.Code, parent); err != nil {
		t.Errorf("RedeemClaim by a current issuer: %v", err)
	}
}
