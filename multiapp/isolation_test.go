package multiapp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// provisionedLogins provisions apps and returns them as isolation check
// subjects.
func provisionedLogins(f *pgFixture, slugs ...string) (string, []AppDatabaseLogin) {
	owner, pools := f.provisionedApps(slugs...)
	apps := make([]AppDatabaseLogin, len(slugs))
	for i, s := range slugs {
		apps[i] = AppDatabaseLogin{Slug: s, Schema: SchemaFromAppSlug(s), Pool: pools[i]}
	}
	return owner, apps
}

func TestSearchPathNames(t *testing.T) {
	got := searchPathNames(`"$user", public, "App ""x""",app_two`)
	want := []string{"$user", "public", `App "x"`, "app_two"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("searchPathNames = %q, want %q", got, want)
	}
}

func TestProvisionedAppsPassTheIsolationCheck(t *testing.T) {
	f := newPGFixture(t)
	owner, apps := provisionedLogins(f, "one", "two")
	if err := CheckDatabaseIsolation(context.Background(), apps, owner); err != nil {
		t.Fatalf("CheckDatabaseIsolation: %v", err)
	}
}

// TestAppLoginCannotReachAnotherAppsSchema tries the ways out of an app's
// schema that SQL running as its login has.
func TestAppLoginCannotReachAnotherAppsSchema(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	owner, apps := provisionedLogins(f, "one", "two")
	one := apps[0].Pool
	twoRole := f.name("sfapp_two")

	for _, stmt := range []string{
		"SELECT * FROM app_two.notes",
		`SELECT * FROM "app_two"."notes"`,
		"INSERT INTO app_two.notes (body) VALUES ('x')",
		"CREATE TABLE app_two.planted (x int)",
		"SET ROLE " + quoteIdent(twoRole),
		"SET ROLE " + quoteIdent(owner),
		"SET SESSION AUTHORIZATION " + quoteIdent(twoRole),
	} {
		if _, err := one.Exec(ctx, stmt); !isPermissionDenied(err) {
			t.Errorf("%s: %v, want permission denied", stmt, err)
		}
	}

	// RESET ROLE and a search_path naming the other schema change nothing:
	// the login itself has no privilege there.
	conn, err := one.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	for _, stmt := range []string{"RESET ROLE", "SET ROLE NONE", "SET search_path TO app_two, public"} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	var schemas []string
	if err := conn.QueryRow(ctx, "SELECT current_schemas(false)").Scan(&schemas); err != nil {
		t.Fatal(err)
	}
	for _, s := range schemas {
		if s == "app_two" {
			t.Errorf("search_path reaches app_two: %v", schemas)
		}
	}
	if _, err := conn.Exec(ctx, "SELECT * FROM app_two.notes"); !isPermissionDenied(err) {
		t.Errorf("after RESET ROLE: %v, want permission denied", err)
	}
	if _, err := conn.Exec(ctx, "RESET ALL"); err != nil {
		t.Fatal(err)
	}
}

// TestIsolationCheckCatchesViolations breaks one app's isolation at a time
// and expects the check to name it.
func TestIsolationCheckCatchesViolations(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	owner, apps := provisionedLogins(f, "one", "two")
	oneRole := quoteIdent(f.name("sfapp_one"))
	twoRole := quoteIdent(f.name("sfapp_two"))

	cases := []struct {
		name        string
		break_, fix []string
		want        string
	}{
		{"cross-schema usage", []string{"GRANT USAGE ON SCHEMA app_two TO " + oneRole}, []string{"REVOKE USAGE ON SCHEMA app_two FROM " + oneRole}, `has USAGE on schema "app_two"`},
		{"cross-schema table grant", []string{"GRANT USAGE ON SCHEMA app_two TO " + oneRole, "GRANT SELECT ON app_two.notes TO " + oneRole}, []string{"REVOKE SELECT ON app_two.notes FROM " + oneRole, "REVOKE USAGE ON SCHEMA app_two FROM " + oneRole}, "reading app_two.notes of another app: allowed"},
		{"cross-schema create", []string{"GRANT USAGE, CREATE ON SCHEMA app_two TO " + oneRole}, []string{"REVOKE USAGE, CREATE ON SCHEMA app_two FROM " + oneRole}, `has CREATE on schema "app_two"`},
		{"superuser", []string{"ALTER ROLE " + oneRole + " SUPERUSER"}, []string{"ALTER ROLE " + oneRole + " NOSUPERUSER"}, "is a superuser"},
		{"bypassrls", []string{"ALTER ROLE " + oneRole + " BYPASSRLS"}, []string{"ALTER ROLE " + oneRole + " NOBYPASSRLS"}, "has BYPASSRLS"},
		{"member of other app", []string{"GRANT " + twoRole + " TO " + oneRole}, []string{"REVOKE " + twoRole + " FROM " + oneRole}, "member of another app's role"},
		{"member of owner", []string{"GRANT " + quoteIdent(owner) + " TO " + oneRole}, []string{"REVOKE " + quoteIdent(owner) + " FROM " + oneRole}, "member of owner (migration) role"},
		{"member of pg_read_all_data", []string{"GRANT pg_read_all_data TO " + oneRole}, []string{"REVOKE pg_read_all_data FROM " + oneRole}, `member of "pg_read_all_data"`},
		{"public create", []string{"GRANT CREATE ON SCHEMA public TO " + oneRole}, []string{"REVOKE CREATE ON SCHEMA public FROM " + oneRole}, "can create objects in schema public"},
		{"search_path", []string{"ALTER ROLE " + oneRole + " SET search_path TO app_one, app_two, public"}, []string{"ALTER ROLE " + oneRole + " SET search_path TO app_one, public"}, `reaches schema "app_two"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.exec(tc.break_...)
			// Role settings apply to new sessions.
			apps[0].Pool.Reset()
			err := CheckDatabaseIsolation(ctx, apps, owner)
			f.exec(tc.fix...)
			apps[0].Pool.Reset()
			var ie *IsolationError
			if !errors.As(err, &ie) {
				t.Fatalf("check passed or failed to run: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), `app "one"`) {
				t.Errorf("error lacks %q for app one:\n%v", tc.want, err)
			}
		})
	}
	if err := CheckDatabaseIsolation(ctx, apps, owner); err != nil {
		t.Fatalf("after fixes: %v", err)
	}

	// Two apps on one login.
	shared := []AppDatabaseLogin{apps[0], {Slug: "two", Schema: "app_two", Pool: apps[0].Pool}}
	if err := CheckDatabaseIsolation(ctx, shared, owner); err == nil || !strings.Contains(err.Error(), "shares database login") {
		t.Errorf("shared login: %v", err)
	}
	// The owner as an app login.
	ownerApp := []AppDatabaseLogin{{Slug: "one", Schema: "app_one", Pool: f.loginPool(owner)}, apps[1]}
	if err := CheckDatabaseIsolation(ctx, ownerApp, owner); err == nil || !strings.Contains(err.Error(), "owns schema") {
		t.Errorf("owner login: %v", err)
	}
}
