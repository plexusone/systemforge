package managedprincipal

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/human"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/internal/pgtest"
	"github.com/plexusone/systemforge/marketplace"
)

// The SystemAuth server is the production gate, and the service checks
// marketplace purchasers.
var (
	_ Gate                         = (*systemauth.Server)(nil)
	_ marketplace.PurchaserChecker = (*Service)(nil)
)

type gate map[string]bool

func (g gate) ManagedPrincipalsAllowed(_ context.Context, clientID string) (bool, error) {
	return g[clientID], nil
}

func (g gate) LoginTokenPolicy(_ context.Context, clientID string) (credential.LoginTokenPolicy, error) {
	if clientID == schoolClient {
		return credential.LoginTokenPolicy{DefaultTTL: schoolYear}, nil
	}
	return credential.LoginTokenPolicy{}, nil
}

type recorder struct {
	mu     sync.Mutex
	events []*audit.Event
}

func (r *recorder) Emit(_ context.Context, e *audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) types() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.events))
	for _, e := range r.events {
		out = append(out, e.EventType)
	}
	return out
}

const (
	client       = "learning-app"
	schoolClient = "school-app"
	schoolYear   = 300 * 24 * time.Hour
)

func openSQLite(t *testing.T) *ent.Client {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return db
}

func newService(t *testing.T, db *ent.Client) (*Service, *recorder) {
	t.Helper()
	rec := &recorder{}
	return NewService(db, gate{client: true, schoolClient: true}, WithAuditEmitter(rec)), rec
}

// addHuman creates a human principal; an empty email creates one without.
func addHuman(t *testing.T, db *ent.Client, email string, active bool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	identifier := "human:" + id.String()
	if email != "" {
		identifier = email
	}
	if _, err := db.Principal.Create().SetID(id).SetType(entprincipal.TypeHuman).
		SetIdentifier(identifier).SetDisplayName("H").SetActive(active).Save(ctx); err != nil {
		t.Fatalf("principal: %v", err)
	}
	c := db.Human.Create().SetPrincipalID(id)
	if email != "" {
		c.SetEmail(email)
	}
	if _, err := c.Save(ctx); err != nil {
		t.Fatalf("human: %v", err)
	}
	return id
}

func TestCreate(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, rec := newService(t, db)
	teacher := addHuman(t, db, "teacher@example.com", true)

	id, err := svc.Create(ctx, CreateInput{
		ClientID:    client,
		DisplayName: "Learner",
		Managers:    []ManagerInput{{PrincipalID: teacher, Role: RoleEducator}},
		ActorID:     teacher,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	p, err := db.Principal.Get(ctx, id)
	if err != nil {
		t.Fatalf("get principal: %v", err)
	}
	if p.Identifier != "human:"+id.String() || p.Type != entprincipal.TypeHuman || !p.Active {
		t.Errorf("principal = %+v", p)
	}
	if !p.Capabilities["can_access_ui"] || p.Capabilities["can_manage_profile"] || p.Capabilities["can_delegate"] {
		t.Errorf("capabilities = %v", p.Capabilities)
	}
	managed, err := svc.IsManaged(ctx, id)
	if err != nil || !managed {
		t.Errorf("IsManaged = %v, %v; want true", managed, err)
	}
	if managed, err := svc.IsManaged(ctx, teacher); err != nil || managed {
		t.Errorf("IsManaged(teacher) = %v, %v; want false", managed, err)
	}
	rels, err := svc.ListManagers(ctx, id)
	if err != nil {
		t.Fatalf("ListManagers: %v", err)
	}
	if len(rels) != 1 || rels[0].ManagerPrincipalID != teacher || rels[0].Role != RoleEducator {
		t.Errorf("managers = %+v", rels)
	}
	if got := rec.types(); len(got) != 1 || got[0] != EventCreated {
		t.Errorf("audit = %v", got)
	}
}

func TestCreateRefusals(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, _ := newService(t, db)
	teacher := addHuman(t, db, "teacher@example.com", true)
	inactive := addHuman(t, db, "gone@example.com", false)
	learner := addHuman(t, db, "", true)
	missing := uuid.New()
	svc.roles = append(svc.roles, "coach")

	tests := []struct {
		name string
		in   CreateInput
		want error
	}{
		{"client not allowed", CreateInput{ActorID: teacher, DisplayName: "Learner", ClientID: "other", Managers: []ManagerInput{{teacher, RoleGuardian}}}, ErrNotAllowed},
		{"no display name", CreateInput{ActorID: teacher, ClientID: client, Managers: []ManagerInput{{teacher, RoleGuardian}}}, ErrDisplayNameRequired},
		{"no managers", CreateInput{DisplayName: "Learner", ClientID: client}, ErrNoManagers},
		{"unknown role", CreateInput{ActorID: teacher, DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{teacher, "parent"}}}, ErrInvalidRole},
		{"inactive manager", CreateInput{ActorID: inactive, DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{inactive, RoleGuardian}}}, ErrInvalidManager},
		{"managed manager", CreateInput{ActorID: learner, DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{learner, RoleGuardian}}}, ErrInvalidManager},
		{"missing manager", CreateInput{ActorID: missing, DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{missing, RoleGuardian}}}, ErrInvalidManager},
		{"one bad manager", CreateInput{ActorID: teacher, DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{teacher, RoleEducator}, {learner, RoleGuardian}}}, ErrInvalidManager},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := svc.Create(ctx, tt.in); !errors.Is(err, tt.want) {
				t.Errorf("Create error = %v, want %v", err, tt.want)
			}
		})
	}
	// Nothing was created: only the three seeded humans exist, and the
	// failed transactions left no relationships behind.
	if n, err := db.Human.Query().Count(ctx); err != nil || n != 3 {
		t.Errorf("humans = %d, %v; want 3", n, err)
	}
	if n, err := db.ManagerRelationship.Query().Count(ctx); err != nil || n != 0 {
		t.Errorf("relationships = %d, %v; want 0", n, err)
	}

	// A registered role is accepted.
	if _, err := svc.Create(ctx, CreateInput{ActorID: teacher, DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{teacher, "coach"}}}); err != nil {
		t.Errorf("Create with registered role: %v", err)
	}
}

func TestWithRoles(t *testing.T) {
	svc := NewService(nil, gate{}, WithRoles("coach", "", RoleGuardian, "coach"))
	got := svc.Roles()
	want := []string{RoleGuardian, RoleEducator, "coach"}
	if len(got) != len(want) {
		t.Fatalf("Roles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Roles = %v, want %v", got, want)
		}
	}
}

func TestAddAndRemoveManager(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, rec := newService(t, db)
	teacher := addHuman(t, db, "teacher@example.com", true)
	parent := addHuman(t, db, "parent@example.com", true)

	id, err := svc.Create(ctx, CreateInput{DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{teacher, RoleGuardian}}, ActorID: teacher})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The only manager cannot be removed.
	if err := svc.RemoveManager(ctx, id, ManagerInput{teacher, RoleGuardian}, teacher); !errors.Is(err, ErrLastManager) {
		t.Fatalf("RemoveManager last = %v, want ErrLastManager", err)
	}

	// Adding is idempotent.
	for range 2 {
		if err := svc.AddManager(ctx, id, ManagerInput{parent, RoleGuardian}, teacher); err != nil {
			t.Fatalf("AddManager: %v", err)
		}
	}
	if n, err := db.ManagerRelationship.Query().Count(ctx); err != nil || n != 2 {
		t.Errorf("relationships = %d, %v; want 2", n, err)
	}
	if err := svc.AddManager(ctx, id, ManagerInput{id, RoleGuardian}, teacher); !errors.Is(err, ErrInvalidManager) {
		t.Errorf("AddManager self = %v, want ErrInvalidManager", err)
	}
	if err := svc.AddManager(ctx, uuid.New(), ManagerInput{parent, RoleGuardian}, teacher); !errors.Is(err, ErrNotManaged) {
		t.Errorf("AddManager to missing principal = %v, want ErrNotManaged", err)
	}

	// With two managers, one can go; then the other is the last.
	if err := svc.RemoveManager(ctx, id, ManagerInput{teacher, RoleGuardian}, parent); err != nil {
		t.Fatalf("RemoveManager: %v", err)
	}
	if err := svc.RemoveManager(ctx, id, ManagerInput{teacher, RoleGuardian}, parent); !errors.Is(err, ErrNotFound) {
		t.Errorf("RemoveManager twice = %v, want ErrNotFound", err)
	}
	if err := svc.RemoveManager(ctx, id, ManagerInput{parent, RoleGuardian}, parent); !errors.Is(err, ErrLastManager) {
		t.Errorf("RemoveManager last = %v, want ErrLastManager", err)
	}
	rels, err := svc.ListManagers(ctx, id)
	if err != nil || len(rels) != 1 || rels[0].ManagerPrincipalID != parent {
		t.Errorf("ListManagers = %+v, %v", rels, err)
	}

	// Re-adding reactivates the soft-deleted relationship.
	if err := svc.AddManager(ctx, id, ManagerInput{teacher, RoleGuardian}, parent); err != nil {
		t.Fatalf("AddManager reactivate: %v", err)
	}
	if n, err := db.ManagerRelationship.Query().Count(ctx); err != nil || n != 2 {
		t.Errorf("relationships after reactivate = %d, %v; want 2", n, err)
	}

	// An unverified email does not let the last manager go.
	if err := db.Human.Update().Where(human.PrincipalID(id)).SetEmail("learner@example.com").Exec(ctx); err != nil {
		t.Fatalf("attach email: %v", err)
	}
	if err := svc.RemoveManager(ctx, id, ManagerInput{teacher, RoleGuardian}, parent); err != nil {
		t.Fatalf("RemoveManager with two managers: %v", err)
	}
	if err := svc.RemoveManager(ctx, id, ManagerInput{parent, RoleGuardian}, parent); !errors.Is(err, ErrLastManager) {
		t.Fatalf("RemoveManager last with unverified email = %v, want ErrLastManager", err)
	}
	if err := svc.AddManager(ctx, id, ManagerInput{teacher, RoleGuardian}, parent); err != nil {
		t.Fatalf("AddManager: %v", err)
	}
	// Once the email is verified, the last manager may be removed.
	if err := svc.VerifyEmail(ctx, id, time.Now()); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	for _, m := range []ManagerInput{{teacher, RoleGuardian}, {parent, RoleGuardian}} {
		if err := svc.RemoveManager(ctx, id, m, parent); err != nil {
			t.Errorf("RemoveManager after email: %v", err)
		}
	}
	// Removing the last manager released the principal.
	if managed, err := svc.IsManaged(ctx, id); err != nil || managed {
		t.Errorf("IsManaged after the last removal = %v, %v; want false", managed, err)
	}
	if p, err := db.Principal.Get(ctx, id); err != nil || !p.Capabilities["can_manage_profile"] {
		t.Errorf("capabilities after release = %v, %v", p.Capabilities, err)
	}

	want := []string{EventCreated, EventManagerAdded, EventManagerAdded, EventManagerRemoved, EventManagerAdded, EventManagerRemoved, EventManagerAdded, EventEmailVerified, EventManagerRemoved, EventManagerRemoved, EventReleased}
	got := rec.types()
	if len(got) != len(want) {
		t.Fatalf("audit = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("audit = %v, want %v", got, want)
		}
	}
}

// openPostgres returns a client on the PostgreSQL test database.
func openPostgres(t *testing.T) *ent.Client {
	t.Helper()
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, pgtest.Open(t))))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// removeConcurrently has each manager removal run at the same moment, as
// actor, and returns their errors in input order.
func removeConcurrently(ctx context.Context, svc *Service, managed uuid.UUID, actor uuid.UUID, ms ...ManagerInput) []error {
	errs := make([]error, len(ms))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, m := range ms {
		wg.Go(func() {
			<-start
			errs[i] = svc.RemoveManager(ctx, managed, m, actor)
		})
	}
	close(start)
	wg.Wait()
	return errs
}

// TestConcurrentRemoveKeepsAManager verifies on PostgreSQL that two
// managers removed concurrently cannot together leave a managed principal
// without one, with exact outcomes: one removal succeeds and the other is
// refused as the last manager.
func TestConcurrentRemoveKeepsAManager(t *testing.T) {
	ctx := context.Background()
	db := openPostgres(t)
	root := uuid.New()
	var svc *Service
	svc = NewService(db, gate{client: true}, WithAuthorizer(rbac.New(
		rbac.WithManagerRoleGetter(func(ctx context.Context, managerID, managedID uuid.UUID) ([]string, error) {
			return svc.ManagerRoles(ctx, managerID, managedID)
		}),
		rbac.WithPlatformAdminChecker(func(_ context.Context, id uuid.UUID) (bool, error) { return id == root, nil }),
		rbac.WithPlatformAdminBypass(true),
	)))

	for range 10 {
		a := addHuman(t, db, uuid.NewString()+"@example.com", true)
		b := addHuman(t, db, uuid.NewString()+"@example.com", true)
		id, err := svc.Create(ctx, CreateInput{ActorID: a, DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{a, RoleGuardian}, {b, RoleEducator}}})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		// A platform administrator's authority does not depend on either
		// removal, so the loser is always refused as the last manager.
		errs := removeConcurrently(ctx, svc, id, root, ManagerInput{a, RoleGuardian}, ManagerInput{b, RoleEducator})
		wins, lastManager := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrLastManager):
				lastManager++
			default:
				t.Fatalf("RemoveManager: %v", err)
			}
		}
		if wins != 1 || lastManager != 1 {
			t.Fatalf("wins = %d, last-manager refusals = %d (errors %v), want 1 and 1", wins, lastManager, errs)
		}
		rels, err := svc.ListManagers(ctx, id)
		if err != nil {
			t.Fatalf("ListManagers: %v", err)
		}
		if len(rels) != 1 {
			t.Fatalf("active managers = %d, want 1", len(rels))
		}
	}
}

// TestConcurrentRemoveByAManagerKeepsAManager verifies on PostgreSQL that a
// guardian acting concurrently to remove herself and a co-manager ends
// consistently: exactly one removal commits, and the other is refused for
// the reason the committed state gives, never both removed and never both
// kept.
func TestConcurrentRemoveByAManagerKeepsAManager(t *testing.T) {
	ctx := context.Background()
	db := openPostgres(t)
	svc, _ := newService(t, db)

	for range 10 {
		a := addHuman(t, db, uuid.NewString()+"@example.com", true)
		b := addHuman(t, db, uuid.NewString()+"@example.com", true)
		id, err := svc.Create(ctx, CreateInput{ActorID: a, DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{a, RoleGuardian}, {b, RoleGuardian}}})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		// Each guardian removes the other, as herself.
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, 2)
		for i, pair := range [][2]uuid.UUID{{a, b}, {b, a}} {
			wg.Go(func() {
				<-start
				errs[i] = svc.RemoveManager(ctx, id, ManagerInput{pair[1], RoleGuardian}, pair[0])
			})
		}
		close(start)
		wg.Wait()
		rels, err := svc.ListManagers(ctx, id)
		if err != nil {
			t.Fatalf("ListManagers: %v", err)
		}
		if len(rels) != 1 {
			t.Fatalf("active managers = %d (errors %v), want 1", len(rels), errs)
		}
		// The survivor is the guardian whose removal of the other
		// committed; the other, having lost her authority, is refused.
		survivor, loser := 0, 1
		if rels[0].ManagerPrincipalID == b {
			survivor, loser = 1, 0
		}
		if errs[survivor] != nil {
			t.Fatalf("surviving guardian's removal = %v, want success", errs[survivor])
		}
		if !errors.Is(errs[loser], ErrForbidden) {
			t.Fatalf("removed guardian's removal = %v, want ErrForbidden", errs[loser])
		}
	}
}

func TestIssueLoginToken(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, rec := newService(t, db)
	now := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	teacher := addHuman(t, db, "teacher@example.com", true)
	parent := addHuman(t, db, "parent@example.com", true)
	stranger := addHuman(t, db, "stranger@example.com", true)
	id, err := svc.Create(ctx, CreateInput{ActorID: teacher, DisplayName: "Learner", ClientID: client,
		Managers: []ManagerInput{{teacher, RoleGuardian}, {parent, RoleGuardian}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	day := 24 * time.Hour
	in := func(mod func(*IssueLoginTokenInput)) IssueLoginTokenInput {
		v := IssueLoginTokenInput{ManagedID: id, ClientID: client, IssuedBy: teacher, Name: "card"}
		mod(&v)
		return v
	}
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }

	for _, tc := range []struct {
		name string
		in   IssueLoginTokenInput
		want time.Time
	}{
		{"platform default", in(func(*IssueLoginTokenInput) {}), now.Add(30 * day)},
		{"client default", in(func(v *IssueLoginTokenInput) { v.ClientID = schoolClient }), now.Add(schoolYear)},
		{"explicit", in(func(v *IssueLoginTokenInput) { v.ExpiresAt = at(7 * day) }), now.Add(7 * day)},
		{"clamped", in(func(v *IssueLoginTokenInput) { v.ExpiresAt = at(500 * day) }), now.Add(400 * day)},
		{"single use", in(func(v *IssueLoginTokenInput) { v.SingleUse = true; v.ClientID = schoolClient }), now.Add(20 * time.Minute)},
		{"guardian", in(func(v *IssueLoginTokenInput) { v.IssuedBy = parent }), now.Add(30 * day)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := svc.IssueLoginToken(ctx, tc.in)
			if err != nil {
				t.Fatalf("IssueLoginToken: %v", err)
			}
			if tok.Credential.PrincipalID != id || tok.Credential.ExpiresAt == nil || !tok.Credential.ExpiresAt.Equal(tc.want) {
				t.Errorf("credential = %+v, want expiry %v", tok.Credential, tc.want)
			}
			issuer, err := credential.LoginTokenIssuedBy(tok.Credential)
			if err != nil || issuer != tc.in.IssuedBy {
				t.Errorf("issued by = %v, %v; want %v", issuer, err, tc.in.IssuedBy)
			}
			if credential.LoginTokenSingleUse(tok.Credential) != tc.in.SingleUse {
				t.Errorf("single use = %v", !tc.in.SingleUse)
			}
		})
	}
	issued := 0
	for _, e := range rec.events {
		if e.EventType == EventTokenIssued {
			issued++
			for _, v := range e.Details {
				if s, ok := v.(string); ok && len(s) > 40 {
					t.Errorf("audit detail %q may hold the plain token", s)
				}
			}
		}
	}
	if issued != 6 {
		t.Errorf("issued audit events = %d, want 6", issued)
	}

	// Refusals.
	if err := svc.RemoveManager(ctx, id, ManagerInput{parent, RoleGuardian}, teacher); err != nil {
		t.Fatalf("RemoveManager: %v", err)
	}
	ordinary := addHuman(t, db, "adult@example.com", true)
	for _, tc := range []struct {
		name string
		in   IssueLoginTokenInput
		want error
	}{
		{"client not allowed", in(func(v *IssueLoginTokenInput) { v.ClientID = "other" }), ErrNotAllowed},
		{"not a manager", in(func(v *IssueLoginTokenInput) { v.IssuedBy = stranger }), ErrNotManager},
		{"removed manager", in(func(v *IssueLoginTokenInput) { v.IssuedBy = parent }), ErrNotManager},
		{"principal has email", in(func(v *IssueLoginTokenInput) { v.ManagedID = ordinary }), ErrNotManaged},
		{"unknown principal", in(func(v *IssueLoginTokenInput) { v.ManagedID = uuid.New() }), ErrNotManaged},
		{"past expiry", in(func(v *IssueLoginTokenInput) { v.ExpiresAt = at(-time.Hour) }), credential.ErrInvalidExpiry},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.IssueLoginToken(ctx, tc.in); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}

	// A manager who is deactivated cannot issue, nor can anyone for a
	// deactivated principal.
	if err := db.Principal.UpdateOneID(teacher).SetActive(false).Exec(ctx); err != nil {
		t.Fatalf("deactivate teacher: %v", err)
	}
	if _, err := svc.IssueLoginToken(ctx, in(func(*IssueLoginTokenInput) {})); !errors.Is(err, ErrNotManager) {
		t.Errorf("inactive manager: %v", err)
	}
	if err := db.Principal.UpdateOneID(id).SetActive(false).Exec(ctx); err != nil {
		t.Fatalf("deactivate learner: %v", err)
	}
	if _, err := svc.IssueLoginToken(ctx, in(func(*IssueLoginTokenInput) {})); !errors.Is(err, ErrNotManaged) {
		t.Errorf("inactive principal: %v", err)
	}
}

// TestManagementIsARelationship verifies ADR-009: a principal is managed
// because it has an active manager, not because it lacks an email.
func TestManagementIsARelationship(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, _ := newService(t, db)
	teacher := addHuman(t, db, "teacher@example.com", true)
	addHuman(t, db, "taken@example.com", true)

	if _, err := svc.Create(ctx, CreateInput{ActorID: teacher, DisplayName: "Student", ClientID: client, Email: "TAKEN@example.com",
		Managers: []ManagerInput{{teacher, RoleGuardian}}}); !errors.Is(err, ErrEmailInUse) {
		t.Fatalf("Create with a taken email = %v, want ErrEmailInUse", err)
	}
	if n, err := db.Human.Query().Count(ctx); err != nil || n != 2 {
		t.Fatalf("humans after refused create = %d, %v; want 2", n, err)
	}

	id, err := svc.Create(ctx, CreateInput{DisplayName: "Student", ClientID: client, Email: "student@example.com",
		Managers: []ManagerInput{{teacher, RoleGuardian}}, ActorID: teacher})
	if err != nil {
		t.Fatalf("Create with email: %v", err)
	}
	h, err := db.Human.Query().Where(human.PrincipalID(id)).Only(ctx)
	if err != nil || h.Email == nil || *h.Email != "student@example.com" || h.EmailVerifiedAt != nil {
		t.Fatalf("human = %+v, %v; want an unverified email", h, err)
	}
	if managed, err := svc.IsManaged(ctx, id); err != nil || !managed {
		t.Errorf("IsManaged with an email = %v, %v; want true", managed, err)
	}
	// Authority checks apply to a managed principal that has an email.
	if _, err := svc.IssueLoginToken(ctx, IssueLoginTokenInput{ManagedID: id, ClientID: client, IssuedBy: teacher}); err != nil {
		t.Errorf("IssueLoginToken for a managed principal with an email: %v", err)
	}
	if _, err := svc.ListLoginTokens(ctx, teacher, id); err != nil {
		t.Errorf("ListLoginTokens: %v", err)
	}

	// The email is unverified, so the only manager cannot go.
	if err := svc.RemoveManager(ctx, id, ManagerInput{teacher, RoleGuardian}, teacher); !errors.Is(err, ErrLastManager) {
		t.Errorf("RemoveManager with an unverified email = %v, want ErrLastManager", err)
	}
	if err := svc.VerifyEmail(ctx, addHuman(t, db, "", true), time.Now()); !errors.Is(err, ErrNotManaged) {
		t.Errorf("VerifyEmail for an unmanaged principal = %v, want ErrNotManaged", err)
	}
	if err := svc.VerifyEmail(ctx, id, time.Now()); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	// A human without a manager is not managed, whatever its email, and
	// cannot be given a manager by AddManager: that takes consent.
	plain := addHuman(t, db, "plain@example.com", true)
	noEmail := addHuman(t, db, "", true)
	for _, id := range []uuid.UUID{plain, noEmail} {
		if managed, err := svc.IsManaged(ctx, id); err != nil || managed {
			t.Errorf("IsManaged(unmanaged) = %v, %v; want false", managed, err)
		}
		if err := svc.AddManager(ctx, id, ManagerInput{teacher, RoleGuardian}, teacher); !errors.Is(err, ErrNotManaged) {
			t.Errorf("AddManager to an unmanaged principal = %v, want ErrNotManaged", err)
		}
	}
	if _, err := svc.IssueLoginToken(ctx, IssueLoginTokenInput{ManagedID: noEmail, ClientID: client, IssuedBy: teacher}); !errors.Is(err, ErrNotManaged) {
		t.Errorf("IssueLoginToken for an unmanaged human = %v, want ErrNotManaged", err)
	}
}

func TestRelease(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, rec := newService(t, db)
	teacher := addHuman(t, db, "teacher@example.com", true)
	parent := addHuman(t, db, "parent@example.com", true)
	id, err := svc.Create(ctx, CreateInput{DisplayName: "Student", ClientID: client, Email: "student@example.com",
		Managers: []ManagerInput{{teacher, RoleEducator}, {parent, RoleGuardian}}, ActorID: parent})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// An unverified email cannot end management.
	if err := svc.Release(ctx, parent, id); !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("Release with an unverified email = %v, want ErrEmailNotVerified", err)
	}
	if err := svc.VerifyEmail(ctx, id, time.Now()); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	// An educator lacks manage_managers.
	if err := svc.Release(ctx, teacher, id); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Release by an educator = %v, want ErrForbidden", err)
	}
	if err := svc.Release(ctx, parent, id); err != nil {
		t.Fatalf("Release: %v", err)
	}

	if managed, err := svc.IsManaged(ctx, id); err != nil || managed {
		t.Errorf("IsManaged after release = %v, %v; want false", managed, err)
	}
	if rels, err := svc.ListManagers(ctx, id); err != nil || len(rels) != 0 {
		t.Errorf("managers after release = %+v, %v", rels, err)
	}
	p, err := db.Principal.Get(ctx, id)
	if err != nil || !p.Capabilities["can_manage_profile"] || !p.Active || p.Identifier != "student@example.com" {
		t.Errorf("principal after release = %+v, %v", p, err)
	}
	if got := rec.types(); got[len(got)-1] != EventReleased {
		t.Errorf("audit = %v, want a final %s", got, EventReleased)
	}
	// The principal is self-managed now: a manager cannot act on it, or
	// release it again.
	if err := svc.Release(ctx, parent, id); !errors.Is(err, ErrNotManaged) {
		t.Errorf("second Release = %v, want ErrNotManaged", err)
	}
	if _, err := svc.IssueLoginToken(ctx, IssueLoginTokenInput{ManagedID: id, ClientID: client, IssuedBy: parent}); !errors.Is(err, ErrNotManaged) {
		t.Errorf("IssueLoginToken after release = %v, want ErrNotManaged", err)
	}
	if err := svc.AddManager(ctx, id, ManagerInput{parent, RoleGuardian}, parent); !errors.Is(err, ErrNotManaged) {
		t.Errorf("AddManager after release = %v, want ErrNotManaged", err)
	}
}

// TestManagedPrincipalCannotManage verifies that a managed principal is
// not a valid manager even when it has an email (ADR-009).
func TestManagedPrincipalCannotManage(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, _ := newService(t, db)
	teacher := addHuman(t, db, "teacher@example.com", true)
	student, err := svc.Create(ctx, CreateInput{ActorID: teacher, DisplayName: "Student", ClientID: client, Email: "student@example.com",
		Managers: []ManagerInput{{teacher, RoleGuardian}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Create(ctx, CreateInput{ActorID: student, DisplayName: "Sibling", ClientID: client,
		Managers: []ManagerInput{{student, RoleGuardian}}}); !errors.Is(err, ErrInvalidManager) {
		t.Errorf("Create with a managed manager = %v, want ErrInvalidManager", err)
	}
	other, err := svc.Create(ctx, CreateInput{ActorID: teacher, DisplayName: "Other", ClientID: client, Managers: []ManagerInput{{teacher, RoleGuardian}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := svc.AddManager(ctx, other, ManagerInput{student, RoleEducator}, teacher); !errors.Is(err, ErrInvalidManager) {
		t.Errorf("AddManager with a managed manager = %v, want ErrInvalidManager", err)
	}
}
