package signupgate

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
)

func newWaitlist(t *testing.T) *Waitlist {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("closing ent client: %v", err)
		}
	})
	return NewWaitlist(db)
}

func TestWaitlistJoinIsIdempotentAndRefreshesConsent(t *testing.T) {
	w, ctx := newWaitlist(t), t.Context()
	if err := w.Join(ctx, "Ada@Example.com", "1", "first text"); err != nil {
		t.Fatal(err)
	}
	if err := w.Join(ctx, "grace@example.com", "1", "first text"); err != nil {
		t.Fatal(err)
	}
	if err := w.Join(ctx, "ada@example.com", "2", "second text"); err != nil {
		t.Fatalf("joining again: %v", err)
	}
	list, err := w.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Email != "ada@example.com" || list[1].Email != "grace@example.com" {
		t.Fatalf("list = %+v, want ada then grace, once each", list)
	}
	if list[0].ConsentVersion != "2" || list[0].ConsentText != "second text" {
		t.Errorf("consent not refreshed: %+v", list[0])
	}
	if err := w.Join(ctx, "not an email", "1", "t"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("malformed address: %v", err)
	}
}

func TestWaitlistRemoveAndCSV(t *testing.T) {
	w, ctx := newWaitlist(t), t.Context()
	for _, e := range []string{"ada@example.com", "grace@example.com"} {
		if err := w.Join(ctx, e, "1", "t"); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Remove(ctx, "ADA@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := w.Remove(ctx, "ada@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing twice: %v", err)
	}
	list, err := w.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteWaitlistCSV(&buf, list); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 || lines[0] != "email,joined_at,last_submitted_at,consent_version,invited_at" || !strings.HasPrefix(lines[1], "grace@example.com,") {
		t.Fatalf("csv = %q", buf.String())
	}
}

func TestWaitlistInviteMarksEntriesAndKeepsThem(t *testing.T) {
	client := newClient(t)
	w, invites, ctx := NewWaitlist(client), NewStore(client), t.Context()
	for _, e := range []string{"ada@example.com", "grace@example.com"} {
		if err := w.Join(ctx, e, "v1", "Tell me"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := w.Invite(ctx, invites, []string{"ADA@example.com", "nobody@example.com"}, AddOptions{Note: "from waitlist"})
	if len(got) != 1 || got[0].Email != "ada@example.com" || got[0].Note != "from waitlist" {
		t.Errorf("invited = %+v", got)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("an address not on the waitlist: %v, want ErrNotFound", err)
	}
	if ok, _ := invites.Allowed(ctx, "ada@example.com"); !ok {
		t.Error("no email invite was created")
	}
	entries, err := w.List(ctx)
	if err != nil || len(entries) != 2 {
		t.Fatalf("entries = %+v, %v; invited entries stay listed", entries, err)
	}
	for _, e := range entries {
		if (e.Email == "ada@example.com") != (e.InvitedAt != nil) {
			t.Errorf("%s invited_at = %v", e.Email, e.InvitedAt)
		}
	}
	if err := w.Join(ctx, "ada@example.com", "v2", "Tell me again"); err != nil {
		t.Fatal(err)
	}
	if entries, _ := w.List(ctx); entries[0].InvitedAt == nil {
		t.Error("joining again cleared invited_at")
	}
}
