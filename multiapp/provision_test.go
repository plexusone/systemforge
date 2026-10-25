package multiapp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestRoleProvisioningSQLQuotesAndValidates(t *testing.T) {
	p := RoleProvisioning{
		Schema:           "app_one",
		Role:             "app_one_login",
		OwnerRole:        "sf_owner",
		Database:         "platform",
		SharedReadTables: []string{"sf_principals"},
		MemberOf:         []string{"rds_iam"},
	}
	stmts, err := p.SQL()
	if err != nil {
		t.Fatalf("SQL: %v", err)
	}
	sql := strings.Join(stmts, ";\n")
	for _, want := range []string{
		`CREATE ROLE "app_one_login" WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION`,
		`rolname = 'app_one_login'`,
		`GRANT CONNECT ON DATABASE "platform" TO "app_one_login"`,
		`CREATE SCHEMA IF NOT EXISTS "app_one" AUTHORIZATION "sf_owner"`,
		`REVOKE ALL ON SCHEMA "app_one" FROM PUBLIC`,
		`GRANT USAGE ON SCHEMA "app_one" TO "app_one_login"`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "app_one" TO "app_one_login"`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE "sf_owner" IN SCHEMA "app_one" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "app_one_login"`,
		`ALTER DEFAULT PRIVILEGES FOR ROLE "sf_owner" REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`,
		`REVOKE CREATE ON SCHEMA public FROM PUBLIC`,
		`to_regclass('"public"."sf_principals"') IS NOT NULL THEN GRANT SELECT ON TABLE "public"."sf_principals" TO "app_one_login"`,
		`GRANT "rds_iam" TO "app_one_login"`,
		`ALTER ROLE "app_one_login" SET search_path TO "app_one", "public"`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL lacks %q", want)
		}
	}
	if strings.Contains(strings.ToUpper(sql), "PASSWORD") {
		t.Error("provisioning SQL mentions a password")
	}

	p.ReadOnly = true
	stmts, err = p.SQL()
	if err != nil {
		t.Fatal(err)
	}
	sql = strings.Join(stmts, ";\n")
	if strings.Contains(sql, "INSERT") || !strings.Contains(sql, `GRANT SELECT ON ALL TABLES IN SCHEMA "app_one"`) {
		t.Error("ReadOnly still grants writes")
	}
}

func TestRoleProvisioningSharedTablesDefault(t *testing.T) {
	grants := func(p RoleProvisioning) []string {
		t.Helper()
		stmts, err := p.SQL()
		if err != nil {
			t.Fatalf("SQL: %v", err)
		}
		var tables []string
		for _, s := range stmts {
			if _, rest, ok := strings.Cut(s, `GRANT SELECT ON TABLE "public".`); ok {
				name, _, _ := strings.Cut(rest, " ")
				tables = append(tables, strings.Trim(name, `"`))
			}
		}
		return tables
	}
	base := RoleProvisioning{Schema: "app_one", Role: "app_one_login", OwnerRole: "sf_owner"}

	if got := grants(base); strings.Join(got, ",") != strings.Join(DefaultSharedReadTables, ",") {
		t.Errorf("default grants %v, want %v", got, DefaultSharedReadTables)
	}
	none := base
	none.SharedReadTables = NoSharedReadTables
	if got := grants(none); len(got) != 0 {
		t.Errorf("opt-out grants %v, want none", got)
	}
	one := base
	one.SharedReadTables = []string{"sf_organizations"}
	if got := grants(one); strings.Join(got, ",") != "sf_organizations" {
		t.Errorf("explicit list grants %v", got)
	}
	for _, restricted := range RestrictedSharedTables {
		if slices.Contains(DefaultSharedReadTables, restricted) {
			t.Errorf("default shared tables include restricted %q", restricted)
		}
		p := base
		p.SharedReadTables = append(slices.Clone(DefaultSharedReadTables), restricted)
		if _, err := p.SQL(); err == nil {
			t.Errorf("shared table %q accepted", restricted)
		}
	}
}

func TestRoleProvisioningRefusesUnsafeNames(t *testing.T) {
	base := RoleProvisioning{Schema: "app_one", Role: "app_one_login", OwnerRole: "sf_owner"}
	if _, err := base.SQL(); err != nil {
		t.Fatalf("valid plan refused: %v", err)
	}
	mutations := map[string]func(p *RoleProvisioning){
		"same role and owner": func(p *RoleProvisioning) { p.OwnerRole = p.Role },
		"missing owner":       func(p *RoleProvisioning) { p.OwnerRole = "" },
		"shared is app":       func(p *RoleProvisioning) { p.SharedSchema = "app_one" },
		"member of owner":     func(p *RoleProvisioning) { p.MemberOf = []string{"sf_owner"} },
	}
	for _, bad := range unsafeSchemaNames {
		mutations["schema "+bad] = func(p *RoleProvisioning) { p.Schema = bad }
		mutations["role "+bad] = func(p *RoleProvisioning) { p.Role = bad }
		mutations["owner "+bad] = func(p *RoleProvisioning) { p.OwnerRole = bad }
		mutations["database "+bad] = func(p *RoleProvisioning) { p.Database = bad }
		mutations["shared schema "+bad] = func(p *RoleProvisioning) { p.SharedSchema = bad }
		mutations["table "+bad] = func(p *RoleProvisioning) { p.SharedReadTables = []string{bad} }
		mutations["member "+bad] = func(p *RoleProvisioning) { p.MemberOf = []string{bad} }
	}
	for name, mutate := range mutations {
		p := base
		mutate(&p)
		if _, err := p.SQL(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, bad := range unsafeSchemaNames {
		if _, err := OwnerRoleSQL(bad); err == nil {
			t.Errorf("OwnerRoleSQL(%q) accepted", bad)
		}
	}
}

// testPassword builds a password at run time.
func testPassword(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "Pw-" + hex.EncodeToString(b) + "'\"x"
}

func TestSCRAMVerifierRefusesNonASCII(t *testing.T) {
	for _, pw := range []string{"", "pässword", "tab\there"} {
		if _, err := scramSHA256Verifier(pw); err == nil {
			t.Errorf("verifier for %q accepted", pw)
		}
	}
}

// TestSCRAMVerifierMatchesPostgres has the server hash a password, then
// recomputes the verifier from its salt and iteration count.
func TestSCRAMVerifierMatchesPostgres(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	role := f.name("sfpw")
	f.dropRolesLater(role)
	f.exec("CREATE ROLE " + quoteIdent(role) + " LOGIN")
	pw := testPassword(t)
	if _, err := f.admin.Exec(ctx, "ALTER ROLE "+quoteIdent(role)+" PASSWORD "+quoteLiteral(pw)); err != nil {
		t.Fatal(err)
	}
	stored := storedVerifier(t, f, role)
	if got := recompute(t, stored, pw); got != stored {
		t.Fatalf("verifier mismatch:\n got %s\nwant %s", got, stored)
	}

	// SetRolePassword stores a verifier for the same password.
	if err := SetRolePassword(ctx, f.admin, role, func(context.Context) (string, error) { return pw, nil }); err != nil {
		t.Fatalf("SetRolePassword: %v", err)
	}
	stored2 := storedVerifier(t, f, role)
	if stored2 == stored || recompute(t, stored2, pw) != stored2 {
		t.Fatalf("SetRolePassword stored %q", stored2)
	}
}

func storedVerifier(t *testing.T, f *pgFixture, role string) string {
	t.Helper()
	var v string
	if err := f.admin.QueryRow(context.Background(), "SELECT rolpassword FROM pg_authid WHERE rolname = $1", role).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// recompute rebuilds a stored SCRAM-SHA-256 verifier with its own salt.
func recompute(t *testing.T, stored, pw string) string {
	t.Helper()
	// SCRAM-SHA-256$<iter>:<salt>$<stored>:<server>
	rest, ok := strings.CutPrefix(stored, "SCRAM-SHA-256$")
	if !ok {
		t.Fatalf("not a SCRAM verifier: %q", stored)
	}
	iterSalt, _, ok := strings.Cut(rest, "$")
	if !ok {
		t.Fatalf("malformed verifier %q", stored)
	}
	iterStr, saltB64, ok := strings.Cut(iterSalt, ":")
	if !ok {
		t.Fatalf("malformed verifier %q", stored)
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		t.Fatal(err)
	}
	v, err := scramVerifierWithSalt(pw, salt, iter)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestProvisionedRolesAreConfined provisions two apps and checks the
// grants: each login reads and writes its own tables, reads the shared
// tables it was granted and nothing else.
func TestProvisionedRolesAreConfined(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	_, pools := f.provisionedApps("one", "two")
	one := pools[0]

	if _, err := one.Exec(ctx, "INSERT INTO notes (body) VALUES ('mine')"); err != nil {
		t.Fatalf("own table through the default search_path: %v", err)
	}
	var n int
	if err := one.QueryRow(ctx, "SELECT count(*) FROM app_one.notes").Scan(&n); err != nil || n != 1 {
		t.Fatalf("own table: %d, %v", n, err)
	}
	if err := one.QueryRow(ctx, "SELECT count(*) FROM sf_principals").Scan(&n); err != nil {
		t.Fatalf("shared read table: %v", err)
	}
	for _, stmt := range []string{
		"INSERT INTO sf_principals (id) VALUES (1)",
		"SELECT * FROM sf_credentials",
		"CREATE TABLE public.planted (x int)",
		"CREATE TABLE app_one.extra (x int)",
		"DROP TABLE app_one.notes",
	} {
		if _, err := one.Exec(ctx, stmt); !isPermissionDenied(err) {
			t.Errorf("%s: %v, want permission denied", stmt, err)
		}
	}

	// Applying again is harmless.
	p := RoleProvisioning{Schema: "app_one", Role: f.name("sfapp_one"), OwnerRole: f.name("sfowner")}
	if err := ApplyRoleProvisioning(ctx, f.admin, p, nil); err != nil {
		t.Fatalf("second apply: %v", err)
	}
}
