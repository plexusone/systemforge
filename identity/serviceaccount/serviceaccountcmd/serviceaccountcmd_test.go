package serviceaccountcmd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/serviceaccount/serviceaccountcmd"
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

// world is an identity database with the team organization "acme" and the
// service-account command over it.
type world struct {
	t     *testing.T
	db    *ent.Client
	reg   *authz.VocabularyRegistry
	roles *approle.Service
	owner uuid.UUID
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
	w := &world{t: t, db: db, reg: reg, roles: approle.NewService(db, reg, approle.EntitleAll(reg))}
	ctx := context.Background()
	owner, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier("owner@example.com").SetDisplayName("Owner").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	w.owner = owner.ID
	if _, err := organization.NewService(db).Create(ctx, organization.CreateOrganizationInput{
		Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &w.owner,
	}); err != nil {
		t.Fatal(err)
	}
	return w
}

// run runs the command with args and returns its output.
func (w *world) run(args ...string) (string, error) {
	w.t.Helper()
	open := func(context.Context) (*ent.Client, func() error, error) {
		return w.db, func() error { return nil }, nil // the test owns the database
	}
	cmd := serviceaccountcmd.Command(open, serviceaccountcmd.Options{
		Service: serviceaccountcmd.DefaultService(w.reg, approle.EntitleAll(w.reg)),
		Issuer:  func() string { return "https://auth.example.com" },
	})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func (w *world) mustRun(args ...string) string {
	w.t.Helper()
	out, err := w.run(args...)
	if err != nil {
		w.t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

// newAccount creates "ci-publisher" and returns its identifier.
func (w *world) newAccount() string {
	w.t.Helper()
	var acct struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal([]byte(w.mustRun("create", "--org", "acme", "--name", "ci-publisher", "--scope", "invoices", "--by", w.owner.String(), "--json")), &acct); err != nil {
		w.t.Fatal(err)
	}
	if !strings.HasPrefix(acct.Identifier, "sa_") {
		w.t.Fatalf("identifier %q", acct.Identifier)
	}
	return acct.Identifier
}

// addKey generates a key into a new file and returns the key ID and file.
func (w *world) addKey(account string) (keyID, path string) {
	w.t.Helper()
	path = filepath.Join(w.t.TempDir(), "key.pem")
	var k struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal([]byte(w.mustRun("key", "add", account, "--out", path, "--json")), &k); err != nil {
		w.t.Fatal(err)
	}
	return k.KeyID, path
}

func TestAccountCommands(t *testing.T) {
	w := newWorld(t)
	sa := w.newAccount()

	if out := w.mustRun("list", "--org", "acme"); !strings.Contains(out, sa) || !strings.Contains(out, "ci-publisher") {
		t.Errorf("list: %s", out)
	}
	if out := w.mustRun("show", sa); !strings.Contains(out, sa) || !strings.Contains(out, "KEY ID") {
		t.Errorf("show: %s", out)
	}
	if out := w.mustRun("disable", sa); out != "disabled "+sa+"\n" {
		t.Errorf("disable: %q", out)
	}
	if out := w.mustRun("show", sa, "--json"); !strings.Contains(out, `"active": false`) {
		t.Errorf("disabled account: %s", out)
	}
	w.mustRun("enable", sa)
	w.mustRun("role", "grant", sa, "--app", "billing", "--role", "viewer")
	if _, err := w.run("role", "grant", sa, "--app", "unknown", "--role", "viewer"); err == nil {
		t.Error("role in an unknown application granted")
	}
	w.mustRun("role", "remove", sa, "--app", "billing")
	w.mustRun("delete", sa)
	if _, err := w.run("show", sa); err == nil {
		t.Error("deleted account shown")
	}

	for name, args := range map[string][]string{
		"unknown org":     {"create", "--org", "nope", "--name", "x"},
		"missing name":    {"create", "--org", "acme"},
		"unknown account": {"show", "sa_nope"},
		"bad --by":        {"disable", uuid.NewString(), "--by", "x"},
	} {
		if _, err := w.run(args...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestKeyCommands(t *testing.T) {
	w := newWorld(t)
	sa := w.newAccount()
	keyID, path := w.addKey(sa)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 && os.PathSeparator == '/' {
		t.Errorf("private key mode %o", perm)
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: a file the test created
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "PRIVATE KEY") {
		t.Errorf("private key file: %s", b)
	}
	// The private key is never printed or listed.
	if out := w.mustRun("key", "list", sa, "--json"); strings.Contains(out, "PRIVATE KEY") || !strings.Contains(out, keyID) {
		t.Errorf("key list: %s", out)
	}
	// An existing file is never overwritten.
	if _, err := w.run("key", "add", sa, "--out", path); err == nil {
		t.Error("existing key file overwritten")
	}
	if _, err := w.run("key", "add", sa); err == nil {
		t.Error("key add without --out or --public-key accepted")
	}

	// The text output names what the workload needs.
	out := w.mustRun("key", "add", sa, "--out", filepath.Join(t.TempDir(), "second.pem"))
	for _, want := range []string{"issuer:  https://auth.example.com", "account: " + sa, "key ID:"} {
		if !strings.Contains(out, want) {
			t.Errorf("key add output lacks %q:\n%s", want, out)
		}
	}

	w.mustRun("key", "revoke", sa, keyID, "--reason", "rotated")
	if out := w.mustRun("key", "list", sa); !strings.Contains(out, "revoked") {
		t.Errorf("after revoke: %s", out)
	}
}
