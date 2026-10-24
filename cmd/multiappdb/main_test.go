package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestSQLCommandPrintsQuotedSQL(t *testing.T) {
	cmd := newRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"sql", "--with-owner", "--owner", "sf_owner", "--app", "example", "--role", "app_example_login", "--default-shared-tables"})
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
