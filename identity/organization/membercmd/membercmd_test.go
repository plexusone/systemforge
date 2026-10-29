package membercmd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	entaccesschange "github.com/plexusone/systemforge/identity/ent/accesschange"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/organization/membercmd"
)

// appVocab declares the test application "billing".
type appVocab struct{}

func (appVocab) App() string { return "billing" }
func (appVocab) Roles() authz.RolePermissions {
	return authz.RolePermissions{"viewer": {"invoice.read"}, "admin": {"invoice.read", "app.admin"}}
}
func (appVocab) Hierarchy() authz.RoleHierarchy {
	return authz.RoleHierarchy{"viewer": 10, "admin": 40}
}
func (appVocab) Scopes() []string      { return nil }
func (appVocab) SpiceDBSchema() string { return "" }

type world struct {
	t     *testing.T
	db    *ent.Client
	reg   *authz.VocabularyRegistry
	owner uuid.UUID
	ada   uuid.UUID
	orgID uuid.UUID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	reg := authz.NewVocabularyRegistry()
	if err := reg.Register(appVocab{}); err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, db: db, reg: reg}
	w.owner = w.human("owner@example.com")
	w.ada = w.human("ada@example.com")
	org, err := organization.NewService(db).Create(context.Background(), organization.CreateOrganizationInput{
		Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &w.owner,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.orgID = org.ID
	return w
}

func (w *world) human(email string) uuid.UUID {
	w.t.Helper()
	ctx := context.Background()
	p, err := w.db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(email).SetDisplayName(email).Save(ctx)
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.db.Human.Create().SetPrincipalID(p.ID).SetEmail(email).Save(ctx); err != nil {
		w.t.Fatal(err)
	}
	return p.ID
}

func (w *world) run(opts membercmd.Options, args ...string) (string, error) {
	w.t.Helper()
	open := func(context.Context) (*ent.Client, func() error, error) {
		return w.db, func() error { return nil }, nil // the test owns the database
	}
	cmd := membercmd.Command(open, opts)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func (w *world) withRoles() membercmd.Options {
	return membercmd.Options{Roles: membercmd.DefaultRoles(w.reg, approle.EntitleAll(w.reg))}
}

func TestMemberLifecycle(t *testing.T) {
	w := newWorld(t)
	opts := w.withRoles()
	ctx := context.Background()

	out, err := w.run(opts, "member", "add", "acme", "Ada@Example.com", "--role", "billing:viewer", "--by", w.owner.String())
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	if !strings.Contains(out, "added ada@example.com to acme as member") || !strings.Contains(out, "granted billing:viewer") {
		t.Errorf("add output:\n%s", out)
	}
	m, err := organization.NewService(w.db).GetMembership(ctx, w.orgID, w.ada)
	if err != nil || m.Role != organization.RoleMember {
		t.Fatalf("membership: %+v %v", m, err)
	}

	// Adding again changes the application role and, with --org-role, the
	// organization role.
	out, err = w.run(opts, "member", "add", "acme", w.ada.String(), "--org-role", "admin", "--role", "billing:admin")
	if err != nil || !strings.Contains(out, "from member to admin") {
		t.Fatalf("re-add: %v\n%s", err, out)
	}
	out, err = w.run(opts, "member", "list", "acme", "--json")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	var members []membercmd.Member
	if err := json.Unmarshal([]byte(out), &members); err != nil {
		t.Fatalf("list json: %v\n%s", err, out)
	}
	var found bool
	for _, mm := range members {
		if mm.Email == "ada@example.com" {
			found = true
			if mm.Role != "admin" || mm.AppRoles["billing"] != "admin" {
				t.Errorf("ada listed as %+v", mm)
			}
		}
	}
	if !found || len(members) != 2 {
		t.Fatalf("list: %+v", members)
	}
	out, err = w.run(opts, "member", "list", "acme")
	if err != nil || !strings.Contains(out, "billing:admin") || !strings.Contains(out, "owner@example.com") {
		t.Fatalf("list table: %v\n%s", err, out)
	}

	// Removing only an application role keeps the membership and records
	// the access change (the role changes above recorded theirs).
	before := w.changes(t, w.ada)
	if out, err := w.run(opts, "member", "remove", "acme", "ada@example.com", "--app", "billing"); err != nil {
		t.Fatalf("remove --app: %v\n%s", err, out)
	}
	if n := w.changes(t, w.ada); n != before+1 {
		t.Fatalf("access changes after removing the role = %d, want %d", n, before+1)
	}
	if _, err := organization.NewService(w.db).GetMembership(ctx, w.orgID, w.ada); err != nil {
		t.Fatalf("membership gone after removing a role: %v", err)
	}

	// Removing the member records another change.
	if out, err := w.run(opts, "member", "remove", "acme", "ada@example.com"); err != nil || !strings.Contains(out, "removed ada@example.com from acme") {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	if n := w.changes(t, w.ada); n != before+2 {
		t.Fatalf("access changes after removing the member = %d, want %d", n, before+2)
	}
	if _, err := organization.NewService(w.db).GetMembership(ctx, w.orgID, w.ada); err == nil {
		t.Fatal("membership kept after remove")
	}
}

func (w *world) changes(t *testing.T, pid uuid.UUID) int {
	t.Helper()
	n, err := w.db.AccessChange.Query().Where(entaccesschange.PrincipalID(pid)).Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMemberErrors(t *testing.T) {
	w := newWorld(t)
	for name, args := range map[string][]string{
		"unknown org":       {"member", "add", "nope", "ada@example.com"},
		"unknown person":    {"member", "add", "acme", "nobody@example.com"},
		"unknown principal": {"member", "add", "acme", uuid.NewString()},
		"bad org role":      {"member", "add", "acme", "ada@example.com", "--org-role", "emperor"},
		"bad app role":      {"member", "add", "acme", "ada@example.com", "--role", "billing"},
		"bad by":            {"member", "add", "acme", "ada@example.com", "--by", "x"},
		"remove non-member": {"member", "remove", "acme", "ada@example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := w.run(w.withRoles(), args...); err == nil {
				t.Fatalf("succeeded:\n%s", out)
			}
		})
	}

	// Without vocabularies (the standalone server), memberships work but
	// application roles are refused.
	if out, err := w.run(membercmd.Options{}, "member", "add", "acme", "ada@example.com"); err != nil {
		t.Fatalf("add without vocabularies: %v\n%s", err, out)
	}
	if _, err := w.run(membercmd.Options{}, "member", "add", "acme", "ada@example.com", "--role", "billing:viewer"); err == nil {
		t.Fatal("application role granted without a vocabulary")
	}
}

func TestRenamedSlugResolves(t *testing.T) {
	w := newWorld(t)
	if err := organization.NewService(w.db).Rename(context.Background(), w.orgID, "acme-inc", w.owner); err != nil {
		t.Fatal(err)
	}
	out, err := w.run(w.withRoles(), "member", "add", "acme", "ada@example.com")
	if err != nil || !strings.Contains(out, "to acme-inc") {
		t.Fatalf("add through the old slug: %v\n%s", err, out)
	}
}
