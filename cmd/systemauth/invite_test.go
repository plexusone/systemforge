package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/signupgate"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// runCLI executes the root command with args and returns its output.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(normalizeArgs(args))
	err := root.ExecuteContext(t.Context())
	return out.String(), err
}

func TestInviteCommands(t *testing.T) {
	db := []string{"--db-driver", "sqlite", "--db-dsn", "file:" + filepath.Join(t.TempDir(), "sa.db") + "?_fk=1", "--issuer", "https://auth.example.com"}
	cli := func(args ...string) (string, error) { return runCLI(t, append(args, db...)...) }

	if out, err := cli("migrate"); err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}

	out, err := cli("invite", "add", "Ada@Example.com", "grace@example.com", "--note", "launch", "--expires-in", "168h")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	for _, want := range []string{"invited ada@example.com", "invited grace@example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("add output missing %q:\n%s", want, out)
		}
	}

	out, err = cli("invite", "list")
	if err != nil {
		t.Fatalf("list: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ada@example.com") || !strings.Contains(out, "pending") || !strings.Contains(out, "launch") {
		t.Errorf("list output:\n%s", out)
	}

	if out, err := cli("invite", "add", "not-an-email"); err == nil {
		t.Errorf("malformed address accepted:\n%s", out)
	}

	if out, err := cli("invite", "revoke", "ada@example.com"); err != nil || !strings.Contains(out, "revoked ada@example.com") {
		t.Fatalf("revoke: %v\n%s", err, out)
	}
	if _, err := cli("invite", "revoke", "ada@example.com"); err == nil {
		t.Error("revoking a missing invite succeeded")
	}
	out, _ = cli("invite", "list")
	if strings.Contains(out, "ada@example.com") || !strings.Contains(out, "grace@example.com") {
		t.Errorf("list after revoke:\n%s", out)
	}
}

func TestInviteNeedsADatabase(t *testing.T) {
	if _, err := runCLI(t, "invite", "list", "--issuer", "https://auth.example.com"); err == nil {
		t.Fatal("invite list without a database succeeded")
	}
}

func TestInviteOnlyFlags(t *testing.T) {
	opts := parse(t, "--invite-only", "--signup-denied-url", "https://app.example.com/invite-only")
	if !opts.inviteOnly || opts.signupDenied != "https://app.example.com/invite-only" {
		t.Errorf("flags not parsed: %+v", opts)
	}
	t.Setenv("SYSTEMAUTH_INVITE_ONLY", "true")
	if !parse(t).inviteOnly {
		t.Error("SYSTEMAUTH_INVITE_ONLY ignored")
	}
}

func TestWaitlistCommands(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "sa.db") + "?_fk=1"
	db := []string{"--db-driver", "sqlite", "--db-dsn", dsn, "--issuer", "https://auth.example.com"}
	cli := func(args ...string) (string, error) { return runCLI(t, append(args, db...)...) }
	if out, err := cli("migrate"); err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}
	conn, err := systemauthsvc.OpenDatabase(&systemauth.DatabaseConfig{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	w := signupgate.NewWaitlist(conn.Client)
	for _, e := range []string{"ada@example.com", "grace@example.com"} {
		if err := w.Join(t.Context(), e, "1", "consent"); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := cli("waitlist", "list", "--csv")
	if err != nil || !strings.HasPrefix(out, "email,joined_at,last_submitted_at,consent_version,invited_at\n") || !strings.Contains(out, "grace@example.com,") {
		t.Fatalf("list --csv: %v\n%s", err, out)
	}
	if out, err := cli("waitlist", "remove", "ada@example.com"); err != nil || !strings.Contains(out, "removed ada@example.com") {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	if _, err := cli("waitlist", "remove", "ada@example.com"); err == nil {
		t.Error("removing a missing entry succeeded")
	}
	out, _ = cli("waitlist", "list")
	if strings.Contains(out, "ada@example.com") || !strings.Contains(out, "grace@example.com") {
		t.Errorf("list after remove:\n%s", out)
	}
}
