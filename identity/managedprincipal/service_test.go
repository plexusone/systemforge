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

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/human"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/internal/pgtest"
)

// The SystemAuth server is the production gate.
var _ Gate = (*systemauth.Server)(nil)

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
	svc.roles = append(svc.roles, "coach")

	tests := []struct {
		name string
		in   CreateInput
		want error
	}{
		{"client not allowed", CreateInput{DisplayName: "Learner", ClientID: "other", Managers: []ManagerInput{{teacher, RoleGuardian}}}, ErrNotAllowed},
		{"no display name", CreateInput{ClientID: client, Managers: []ManagerInput{{teacher, RoleGuardian}}}, ErrDisplayNameRequired},
		{"no managers", CreateInput{DisplayName: "Learner", ClientID: client}, ErrNoManagers},
		{"unknown role", CreateInput{DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{teacher, "parent"}}}, ErrInvalidRole},
		{"inactive manager", CreateInput{DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{inactive, RoleGuardian}}}, ErrInvalidManager},
		{"managed manager", CreateInput{DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{learner, RoleGuardian}}}, ErrInvalidManager},
		{"missing manager", CreateInput{DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{uuid.New(), RoleGuardian}}}, ErrInvalidManager},
		{"one bad manager", CreateInput{DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{teacher, RoleEducator}, {learner, RoleGuardian}}}, ErrInvalidManager},
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
	if _, err := svc.Create(ctx, CreateInput{DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{teacher, "coach"}}}); err != nil {
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

	id, err := svc.Create(ctx, CreateInput{DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{teacher, RoleEducator}}, ActorID: teacher})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// The only manager cannot be removed.
	if err := svc.RemoveManager(ctx, id, ManagerInput{teacher, RoleEducator}, teacher); !errors.Is(err, ErrLastManager) {
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
	if err := svc.AddManager(ctx, uuid.New(), ManagerInput{parent, RoleGuardian}, teacher); !errors.Is(err, ErrNotFound) {
		t.Errorf("AddManager to missing principal = %v, want ErrNotFound", err)
	}

	// With two managers, one can go; then the other is the last.
	if err := svc.RemoveManager(ctx, id, ManagerInput{teacher, RoleEducator}, parent); err != nil {
		t.Fatalf("RemoveManager: %v", err)
	}
	if err := svc.RemoveManager(ctx, id, ManagerInput{teacher, RoleEducator}, parent); !errors.Is(err, ErrNotFound) {
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
	if err := svc.AddManager(ctx, id, ManagerInput{teacher, RoleEducator}, parent); err != nil {
		t.Fatalf("AddManager reactivate: %v", err)
	}
	if n, err := db.ManagerRelationship.Query().Count(ctx); err != nil || n != 2 {
		t.Errorf("relationships after reactivate = %d, %v; want 2", n, err)
	}

	// Once the principal has an email, the last manager may be removed.
	if err := db.Human.Update().Where(human.PrincipalID(id)).SetEmail("learner@example.com").Exec(ctx); err != nil {
		t.Fatalf("attach email: %v", err)
	}
	for _, m := range []ManagerInput{{teacher, RoleEducator}, {parent, RoleGuardian}} {
		if err := svc.RemoveManager(ctx, id, m, parent); err != nil {
			t.Errorf("RemoveManager after email: %v", err)
		}
	}

	want := []string{EventCreated, EventManagerAdded, EventManagerAdded, EventManagerRemoved, EventManagerAdded, EventManagerRemoved, EventManagerRemoved}
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

// TestConcurrentRemoveKeepsAManager verifies on PostgreSQL that two
// managers removed concurrently cannot together leave a managed principal
// without one.
func TestConcurrentRemoveKeepsAManager(t *testing.T) {
	ctx := context.Background()
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, pgtest.Open(t))))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	svc, _ := newService(t, db)

	for range 10 {
		a := addHuman(t, db, uuid.NewString()+"@example.com", true)
		b := addHuman(t, db, uuid.NewString()+"@example.com", true)
		id, err := svc.Create(ctx, CreateInput{DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{a, RoleGuardian}, {b, RoleEducator}}})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, m := range []ManagerInput{{a, RoleGuardian}, {b, RoleEducator}} {
			wg.Go(func() { errs[i] = svc.RemoveManager(ctx, id, m, a) })
		}
		wg.Wait()
		rels, err := svc.ListManagers(ctx, id)
		if err != nil {
			t.Fatalf("ListManagers: %v", err)
		}
		if len(rels) != 1 {
			t.Fatalf("active managers = %d (errors %v), want 1", len(rels), errs)
		}
		failed := 0
		for _, err := range errs {
			if errors.Is(err, ErrLastManager) {
				failed++
			} else if err != nil {
				t.Fatalf("RemoveManager: %v", err)
			}
		}
		if failed != 1 {
			t.Fatalf("ErrLastManager count = %d, want 1", failed)
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
	id, err := svc.Create(ctx, CreateInput{DisplayName: "Learner", ClientID: client,
		Managers: []ManagerInput{{teacher, RoleEducator}, {parent, RoleGuardian}}})
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
