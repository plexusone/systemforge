package signupgate

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/systemauth"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("closing ent client: %v", err)
		}
	})
	return NewStore(db)
}

func TestNormalizeEmail(t *testing.T) {
	for in, want := range map[string]string{
		"Ada@Example.COM":   "ada@example.com",
		"  ada@example.com": "ada@example.com",
		"a+tag@example.org": "a+tag@example.org",
	} {
		got, err := NormalizeEmail(in)
		if err != nil || got != want {
			t.Errorf("NormalizeEmail(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ada", "ada@", "@example.com", "Ada <ada@example.com>", "ada@localhost", "a@b.c, d@e.f"} {
		if _, err := NormalizeEmail(bad); !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("NormalizeEmail(%q) accepted", bad)
		}
	}
}

func TestAddIsCaseInsensitiveAndUpdatesPending(t *testing.T) {
	s, ctx := newStore(t), t.Context()
	if _, err := s.Add(ctx, "Ada@Example.com", AddOptions{Note: "first", InvitedBy: "ops"}); err != nil {
		t.Fatal(err)
	}
	inv, err := s.Add(ctx, "ada@example.com", AddOptions{Note: "second"})
	if err != nil {
		t.Fatalf("re-adding a pending invite: %v", err)
	}
	if inv.Note != "second" {
		t.Errorf("note = %q, want the update", inv.Note)
	}
	list, err := s.List(ctx, false)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %+v, %v; want one invite for one address", list, err)
	}
}

func TestInviteLifecycle(t *testing.T) {
	s, ctx := newStore(t), t.Context()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	s.now = func() time.Time { return now }

	if ok, err := s.Allowed(ctx, "ada@example.com"); err != nil || ok {
		t.Fatalf("uninvited allowed = %v, %v", ok, err)
	}
	expiry := now.Add(time.Hour)
	if _, err := s.Add(ctx, "ada@example.com", AddOptions{ExpiresAt: &expiry}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Allowed(ctx, "ADA@example.com"); !ok {
		t.Error("pending invite not allowed, or lookup is case-sensitive")
	}

	now = now.Add(2 * time.Hour)
	if ok, _ := s.Allowed(ctx, "ada@example.com"); ok {
		t.Error("expired invite allowed")
	}

	// A later add without an expiry makes it usable again.
	if _, err := s.Add(ctx, "ada@example.com", AddOptions{}); err != nil {
		t.Fatal(err)
	}
	pid := uuid.New()
	if err := s.Redeem(ctx, "ada@example.com", pid); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Allowed(ctx, "ada@example.com"); ok {
		t.Error("redeemed invite allowed again")
	}
	if _, err := s.Add(ctx, "ada@example.com", AddOptions{}); !errors.Is(err, ErrAlreadyRedeemed) {
		t.Errorf("add after redeem: %v, want ErrAlreadyRedeemed", err)
	}
	// Redeeming twice neither errors nor changes who redeemed it.
	if err := s.Redeem(ctx, "ada@example.com", uuid.New()); err != nil {
		t.Errorf("second redeem: %v", err)
	}
	all, err := s.List(ctx, true)
	if err != nil || len(all) != 1 || all[0].RedeemedBy == nil || *all[0].RedeemedBy != pid {
		t.Fatalf("list = %+v, %v", all, err)
	}
	if got := all[0].Status(now); got != "redeemed" {
		t.Errorf("status = %q", got)
	}
	if pending, _ := s.List(ctx, false); len(pending) != 0 {
		t.Errorf("pending list = %+v, want none", pending)
	}

	if err := s.Revoke(ctx, "ada@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, "ada@example.com"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second revoke: %v, want ErrNotFound", err)
	}
	if _, err := s.Add(ctx, "ada@example.com", AddOptions{}); err != nil {
		t.Errorf("inviting again after revoke: %v", err)
	}
}

func TestGate(t *testing.T) {
	s, ctx := newStore(t), t.Context()
	g := NewGate(s)
	if _, err := s.Add(ctx, "ada@example.com", AddOptions{}); err != nil {
		t.Fatal(err)
	}
	verified := func(email string) systemauth.ExternalLogin {
		return systemauth.ExternalLogin{Provider: "github", Subject: "1", Email: email, EmailVerified: true}
	}

	if err := g.AllowSignup(ctx, verified("ADA@example.com")); err != nil {
		t.Errorf("invited address refused: %v", err)
	}
	if err := g.AllowSignup(ctx, verified("grace@example.com")); !errors.Is(err, systemauth.ErrSignupNotInvited) {
		t.Errorf("uninvited address: %v, want ErrSignupNotInvited", err)
	}
	unverified := verified("ada@example.com")
	unverified.EmailVerified = false
	if err := g.AllowSignup(ctx, unverified); !errors.Is(err, systemauth.ErrSignupNotInvited) {
		t.Errorf("unverified address trusted: %v", err)
	}
	if err := g.AllowSignup(ctx, verified("not an email")); !errors.Is(err, systemauth.ErrSignupNotInvited) {
		t.Errorf("malformed address: %v", err)
	}

	if err := g.SignedUp(ctx, verified("ada@example.com"), uuid.New()); err != nil {
		t.Fatal(err)
	}
	if err := g.AllowSignup(ctx, verified("ada@example.com")); !errors.Is(err, systemauth.ErrSignupNotInvited) {
		t.Errorf("a used invite admits a second sign-up: %v", err)
	}
}
