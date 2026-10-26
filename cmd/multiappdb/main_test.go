package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/multiapp"
)

func TestSQLCommandPrintsQuotedSQL(t *testing.T) {
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"sql", "--with-owner", "--owner", "sf_owner", "--app", "example", "--role", "app_example_login"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	sql := out.String()
	for _, want := range []string{
		`CREATE ROLE "sf_owner"`,
		`CREATE ROLE "app_example_login"`,
		`GRANT USAGE ON SCHEMA "app_example" TO "app_example_login"`,
		`"public"."sf_principals"`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("output lacks %q", want)
		}
	}
}

func TestSQLCommandSharedTables(t *testing.T) {
	run := func(args ...string) (string, error) {
		cmd := newRootCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(append([]string{"sql", "--owner", "sf_owner", "--app", "example", "--role", "app_example_login"}, args...))
		err := cmd.Execute()
		return out.String(), err
	}
	sql, err := run()
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range multiapp.DefaultSharedReadTables {
		if !strings.Contains(sql, `"public"."`+table+`"`) {
			t.Errorf("default output lacks %s", table)
		}
	}
	if sql, err = run("--no-shared-tables"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sql, "GRANT SELECT ON TABLE") {
		t.Error("--no-shared-tables still grants shared tables")
	}
	if sql, err = run("--shared-table", "sf_organizations"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sql, "sf_principals") || !strings.Contains(sql, "sf_organizations") {
		t.Error("--shared-table does not replace the default list")
	}
	if _, err = run("--shared-table", "sf_credentials"); err == nil {
		t.Error("a restricted shared table was accepted")
	}
	if _, err = run("--no-shared-tables", "--shared-table", "sf_organizations"); err == nil {
		t.Error("--no-shared-tables with --shared-table was accepted")
	}
}

func TestSQLCommandRefusesUnsafeNames(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"sql", "--owner", "sf_owner", "--app", "x", "--role", `bad"; DROP ROLE x; --`})
	if err := cmd.Execute(); err == nil {
		t.Fatal("unsafe role name accepted")
	}
}

func TestVerifyRequiresLogins(t *testing.T) {
	cmd := newRootCmd()
	cmd.SetArgs([]string{"verify"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("verify without logins succeeded")
	}
	cmd = newRootCmd()
	cmd.SetArgs([]string{"verify", "--login", "one=SF_TEST_UNSET_VARIABLE_FOR_VERIFY"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "SF_TEST_UNSET_VARIABLE_FOR_VERIFY is empty") {
		t.Fatalf("verify with an unset variable: %v", err)
	}
}
