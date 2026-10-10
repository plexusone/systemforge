package managedprincipal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/authz/rbac"
)

// syncRecorder records manager relation writes and can fail them.
type syncRecorder struct {
	noop.Syncer
	mu   sync.Mutex
	ops  []string
	fail error
}

func (r *syncRecorder) record(op string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ops = append(r.ops, op)
	return r.fail
}

func (r *syncRecorder) AddPrincipalManager(_ context.Context, managed, manager uuid.UUID, role string) error {
	return r.record(fmt.Sprintf("add %s %s %s", managed, manager, role))
}

func (r *syncRecorder) RemovePrincipalManager(_ context.Context, managed, manager uuid.UUID, role string) error {
	return r.record(fmt.Sprintf("remove %s %s %s", managed, manager, role))
}

func TestManagerRelationsSync(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	rec := &syncRecorder{}
	svc := NewService(db, gate{client: true}, WithAuthzSyncer(rec, authz.SyncModeStrict))
	teacher := addHuman(t, db, "teacher@example.com", true)
	parent := addHuman(t, db, "parent@example.com", true)

	id, err := svc.Create(ctx, CreateInput{ActorID: teacher, DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{teacher, RoleGuardian}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.AddManager(ctx, id, ManagerInput{parent, RoleGuardian}, teacher); err != nil {
		t.Fatalf("AddManager: %v", err)
	}
	if err := svc.RemoveManager(ctx, id, ManagerInput{teacher, RoleGuardian}, parent); err != nil {
		t.Fatalf("RemoveManager: %v", err)
	}
	// A refused removal writes nothing.
	if err := svc.RemoveManager(ctx, id, ManagerInput{parent, RoleGuardian}, parent); !errors.Is(err, ErrLastManager) {
		t.Fatalf("RemoveManager last = %v", err)
	}
	want := []string{
		fmt.Sprintf("add %s %s guardian", id, teacher),
		fmt.Sprintf("add %s %s guardian", id, parent),
		fmt.Sprintf("remove %s %s guardian", id, teacher),
	}
	if !slices.Equal(rec.ops, want) {
		t.Errorf("sync ops = %v, want %v", rec.ops, want)
	}

	// Strict mode reports a failed sync; the database change stands.
	rec.fail = errors.New("backend down")
	if err := svc.AddManager(ctx, id, ManagerInput{teacher, RoleGuardian}, parent); err == nil {
		t.Error("strict sync failure not returned")
	}
	if roles, err := svc.ManagerRoles(ctx, teacher, id); err != nil || !slices.Equal(roles, []string{RoleGuardian}) {
		t.Errorf("ManagerRoles after failed sync = %v, %v", roles, err)
	}
	if _, err := svc.Create(ctx, CreateInput{ActorID: teacher, DisplayName: "Learner 2", ClientID: client, Managers: []ManagerInput{{teacher, RoleGuardian}}}); err == nil {
		t.Error("strict sync failure on create not returned")
	}

	// Eventual mode logs it instead.
	eventual := NewService(db, gate{client: true}, WithAuthzSyncer(rec, authz.SyncModeEventual))
	if err := eventual.AddManager(ctx, id, ManagerInput{teacher, RoleGuardian}, parent); err != nil {
		t.Errorf("eventual sync failure returned: %v", err)
	}
}

// TestSimpleProviderWithManagerRoles verifies the simple provider backed
// by the service's ManagerRoles enforces the built-in role permissions.
func TestSimpleProviderWithManagerRoles(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, _ := newService(t, db)
	teacher := addHuman(t, db, "teacher@example.com", true)
	parent := addHuman(t, db, "parent@example.com", true)
	id, err := svc.Create(ctx, CreateInput{ActorID: teacher, DisplayName: "Learner", ClientID: client,
		Managers: []ManagerInput{{teacher, RoleEducator}, {parent, RoleGuardian}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	provider := rbac.New(rbac.WithManagerRoleGetter(svc.ManagerRoles))
	can := func(who uuid.UUID, a authz.Action) bool {
		ok, err := provider.Can(ctx, authz.NewUserPrincipal(who), a, authz.NewPrincipalResource(id))
		if err != nil {
			t.Fatalf("Can: %v", err)
		}
		return ok
	}
	if !can(teacher, authz.PermManageCredentials) || can(teacher, authz.PermManageAccount) {
		t.Error("educator permissions wrong")
	}
	if !can(parent, authz.PermManageAccount) || !can(parent, authz.PermManageManagers) {
		t.Error("guardian permissions wrong")
	}
	if err := svc.RemoveManager(ctx, id, ManagerInput{teacher, RoleEducator}, parent); err != nil {
		t.Fatalf("RemoveManager: %v", err)
	}
	if can(teacher, authz.PermViewProfile) {
		t.Error("removed educator still views the profile")
	}
	if err := db.Principal.UpdateOneID(parent).SetActive(false).Exec(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if can(parent, authz.PermManageAccount) {
		t.Error("deactivated guardian still manages the account")
	}
}

// TestReleaseSyncsEveryManagerRemoval verifies that Release removes each
// manager's relation from the authorization backend.
func TestReleaseSyncsEveryManagerRemoval(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	rec := &syncRecorder{}
	svc := NewService(db, gate{client: true}, WithAuthzSyncer(rec, authz.SyncModeStrict))
	teacher := addHuman(t, db, "teacher@example.com", true)
	parent := addHuman(t, db, "parent@example.com", true)
	id, err := svc.Create(ctx, CreateInput{ActorID: parent, DisplayName: "Learner", ClientID: client, Email: "learner@example.com",
		Managers: []ManagerInput{{parent, RoleGuardian}, {teacher, RoleEducator}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.VerifyEmail(ctx, id, time.Now()); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	rec.ops = nil
	if err := svc.Release(ctx, parent, id); err != nil {
		t.Fatalf("Release: %v", err)
	}
	want := []string{
		fmt.Sprintf("remove %s %s guardian", id, parent),
		fmt.Sprintf("remove %s %s educator", id, teacher),
	}
	slices.Sort(want)
	slices.Sort(rec.ops)
	if !slices.Equal(rec.ops, want) {
		t.Errorf("sync ops = %v, want %v", rec.ops, want)
	}
}
