package admincmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/principal"
)

func TestGrantRevokeList(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing ent client: %v", err)
		}
	})
	if _, err := principal.NewService(client).CreateHuman(t.Context(), principal.CreateHumanInput{Email: "ada@example.com", DisplayName: "Ada"}); err != nil {
		t.Fatal(err)
	}
	open := func(context.Context) (*ent.Client, func() error, error) { //nolint:unparam // matches the Open signature
		return client, func() error { return nil }, nil
	}
	execute := func(args ...string) (string, error) {
		var out bytes.Buffer
		cmd := Command(open)
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		err := cmd.ExecuteContext(t.Context())
		return out.String(), err
	}
	isAdmin := func() bool {
		h, err := client.Human.Query().Where(human.EmailEQ("ada@example.com")).Only(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return h.IsPlatformAdmin
	}

	if out, err := execute("grant", "Ada@Example.com", "nobody@example.com"); err == nil || !strings.Contains(out, "granted ada@example.com") {
		t.Fatalf("grant = %q, %v; want ada granted and the unknown address reported", out, err)
	}
	if !isAdmin() {
		t.Fatal("ada is not a platform admin")
	}
	if out, err := execute("list"); err != nil || !strings.Contains(out, "ada@example.com") {
		t.Errorf("list = %q, %v", out, err)
	}
	if _, err := execute("revoke", "ada@example.com"); err != nil {
		t.Fatal(err)
	}
	if isAdmin() {
		t.Error("ada is still a platform admin")
	}
}
