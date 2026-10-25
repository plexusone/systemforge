package signupcmd

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/identity/signupgate"
)

func testOpen(t *testing.T) (Open, *ent.Client) {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing ent client: %v", err)
		}
	})
	return func(context.Context) (*ent.Client, func() error, error) {
		return client, func() error { return nil }, nil
	}, client
}

func execute(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	return out.String(), err
}

var codePattern = regexp.MustCompile(`code ([0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}) \(id ([0-9a-f-]{36})`)

func TestCodeCommands(t *testing.T) {
	open, client := testOpen(t)
	link := func() string { return "https://auth.example.com/signup" }

	out, err := execute(t, CodeCommand(open, link), "create", "--label", "launch", "--max-uses", "20")
	if err != nil {
		t.Fatal(err)
	}
	m := codePattern.FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "link https://auth.example.com/signup?code="+m[1]) {
		t.Fatalf("create printed %q", out)
	}
	out, err = execute(t, CodeCommand(open, link), "list")
	if err != nil || !strings.Contains(out, m[2]) || !strings.Contains(out, "0/20") || strings.Contains(out, m[1]) {
		t.Fatalf("list = %q, %v; want the code by ID and hint, never in full", out, err)
	}

	store := signupgate.NewCodeStore(client, signupgate.MemberOptions{})
	id, err := store.Reserve(t.Context(), m[1])
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Redeem(t.Context(), id, uuid.New(), "ada@example.com"); err != nil {
		t.Fatal(err)
	}
	if out, err = execute(t, CodeCommand(open, link), "joined", "--label", "launch"); err != nil || !strings.Contains(out, "ada@example.com") {
		t.Errorf("joined = %q, %v", out, err)
	}

	if out, err = execute(t, CodeCommand(open, link), "revoke", m[2], "not-an-id"); err == nil || !strings.Contains(out, "revoked "+m[2]) {
		t.Errorf("revoke = %q, %v; want the valid ID revoked and the bad one reported", out, err)
	}
	if out, _ = execute(t, CodeCommand(open, link), "list"); strings.Contains(out, m[2]) {
		t.Errorf("a revoked code is listed as usable: %q", out)
	}
	if out, _ = execute(t, CodeCommand(open, link), "list", "--all"); !strings.Contains(out, "revoked") {
		t.Errorf("list --all = %q", out)
	}
}

func TestWaitlistInviteCommand(t *testing.T) {
	open, client := testOpen(t)
	w := signupgate.NewWaitlist(client)
	for _, e := range []string{"ada@example.com", "grace@example.com"} {
		if err := w.Join(t.Context(), e, "v1", "Tell me"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := execute(t, WaitlistCommand(open), "invite"); err == nil {
		t.Error("invite with neither addresses nor --all accepted")
	}
	out, err := execute(t, WaitlistCommand(open), "invite", "ada@example.com")
	if err != nil || !strings.Contains(out, "invited ada@example.com") {
		t.Fatalf("invite = %q, %v", out, err)
	}
	out, err = execute(t, WaitlistCommand(open), "invite", "--all")
	if err != nil || !strings.Contains(out, "invited grace@example.com") || strings.Contains(out, "ada@") {
		t.Fatalf("invite --all = %q, %v; want only the entry not yet invited", out, err)
	}
	invites, err := signupgate.NewStore(client).List(t.Context(), false)
	if err != nil || len(invites) != 2 {
		t.Errorf("invites = %+v, %v", invites, err)
	}
}

func TestAllowanceCommands(t *testing.T) {
	open, client := testOpen(t)
	if _, err := principal.NewService(client).CreateHuman(t.Context(), principal.CreateHumanInput{Email: "ada@example.com", DisplayName: "Ada"}); err != nil {
		t.Fatal(err)
	}
	if _, err := execute(t, AllowanceCommand(open), "set", "ada@example.com", "-1"); err == nil {
		t.Error("negative count accepted")
	}
	if _, err := execute(t, AllowanceCommand(open), "set", "nobody@example.com", "3"); err == nil {
		t.Error("an address with no account accepted")
	}
	if out, err := execute(t, AllowanceCommand(open), "set", "ada@example.com", "3", "--note", "early"); err != nil || !strings.Contains(out, "set ada@example.com to 3") {
		t.Fatalf("set = %q, %v", out, err)
	}
	out, err := execute(t, AllowanceCommand(open), "list")
	if err != nil || !strings.Contains(out, "ada@example.com") || !strings.Contains(out, "early") {
		t.Fatalf("list = %q, %v", out, err)
	}
	if _, err := execute(t, AllowanceCommand(open), "set", "ada@example.com", "default"); err != nil {
		t.Fatal(err)
	}
	if out, _ := execute(t, AllowanceCommand(open), "list"); !strings.Contains(out, "default") {
		t.Errorf("after reset, list = %q", out)
	}
}
