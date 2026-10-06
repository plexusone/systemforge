package relyingparty

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestResolvePrincipal(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	sub := "sa-principal-1"
	verified := VerifiedIdentity{Subject: sub, Email: "Octo@Example.com", EmailVerified: true, Name: "Octo"}

	t.Run("creates and then matches by subject", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		p, err := ResolvePrincipal(ctx, store, verified, now)
		if err != nil || p.SFPrincipalID != sub || !p.EmailVerified || !p.Active || p.Type != "human" {
			t.Fatalf("create: %+v %v", p, err)
		}
		// A later login with a changed email still resolves by subject.
		again, err := ResolvePrincipal(ctx, store, VerifiedIdentity{Subject: sub, Email: "new@example.com", EmailVerified: true, Name: "Octo 2"}, now)
		if err != nil || again.ID != p.ID {
			t.Fatalf("by subject: %+v %v", again, err)
		}
		got, err := store.GetPrincipal(ctx, p.ID)
		if err != nil || got.Name != "Octo 2" {
			t.Errorf("profile not refreshed: %+v %v", got, err)
		}
	})

	t.Run("links a verified local email", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		local, err := store.AddPrincipal(Principal{Email: "octo@example.com", EmailVerified: true, Active: true})
		if err != nil {
			t.Fatal(err)
		}
		p, err := ResolvePrincipal(ctx, store, verified, now)
		if err != nil || p.ID != local.ID || p.SFPrincipalID != sub {
			t.Fatalf("link: %+v %v", p, err)
		}
		if found, err := store.FindBySubject(ctx, sub); err != nil || found.ID != local.ID {
			t.Errorf("link not persisted: %v", err)
		}
	})

	t.Run("does not link an unverified local email", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		if _, err := store.AddPrincipal(Principal{Email: "octo@example.com", Active: true}); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolvePrincipal(ctx, store, verified, now); !errors.Is(err, ErrEmailConflict) {
			t.Fatalf("err = %v, want ErrEmailConflict", err)
		}
	})

	t.Run("does not relink a principal linked to another subject", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		if _, err := store.AddPrincipal(Principal{Email: "octo@example.com", EmailVerified: true, Active: true, SFPrincipalID: "other"}); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolvePrincipal(ctx, store, verified, now); !errors.Is(err, ErrEmailConflict) {
			t.Fatalf("err = %v, want ErrEmailConflict", err)
		}
	})

	t.Run("unverified identity email neither links nor creates", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		if _, err := store.AddPrincipal(Principal{Email: "octo@example.com", EmailVerified: true, Active: true}); err != nil {
			t.Fatal(err)
		}
		id := verified
		id.EmailVerified = false
		if _, err := ResolvePrincipal(ctx, store, id, now); !errors.Is(err, ErrEmailNotVerified) {
			t.Fatalf("err = %v, want ErrEmailNotVerified", err)
		}
		if _, err := store.FindBySubject(ctx, sub); !errors.Is(err, ErrPrincipalNotFound) {
			t.Errorf("unverified identity linked: %v", err)
		}
	})

	t.Run("inactive principal", func(t *testing.T) {
		store := NewMemoryPrincipalStore()
		if _, err := store.AddPrincipal(Principal{Email: "x@example.com", Active: false, SFPrincipalID: sub}); err != nil {
			t.Fatal(err)
		}
		if _, err := ResolvePrincipal(ctx, store, verified, now); !errors.Is(err, ErrPrincipalInactive) {
			t.Fatalf("err = %v, want ErrPrincipalInactive", err)
		}
	})

	t.Run("lost race retries by subject", func(t *testing.T) {
		store := &racingStore{MemoryPrincipalStore: NewMemoryPrincipalStore()}
		p, err := ResolvePrincipal(ctx, store, verified, now)
		if err != nil || p.SFPrincipalID != sub {
			t.Fatalf("race: %+v %v", p, err)
		}
	})

	if _, err := ResolvePrincipal(ctx, NewMemoryPrincipalStore(), VerifiedIdentity{}, now); err == nil {
		t.Error("empty subject accepted")
	}
}

// racingStore simulates a concurrent first login winning the subject link.
type racingStore struct {
	*MemoryPrincipalStore
	raced bool
}

func (s *racingStore) CreatePrincipal(ctx context.Context, id VerifiedIdentity) (*Principal, error) {
	if !s.raced {
		s.raced = true
		if _, err := s.MemoryPrincipalStore.CreatePrincipal(ctx, id); err != nil {
			return nil, err
		}
		return nil, ErrSubjectLinked
	}
	return s.MemoryPrincipalStore.CreatePrincipal(ctx, id)
}

func TestMemoryStores(t *testing.T) {
	ctx := t.Context()
	sessions := NewMemorySessionStore()
	now := time.Now()
	sessions.now = func() time.Time { return now }
	if err := sessions.Create(ctx, "tok", Session{PrincipalID: "p", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	for k := range sessions.sessions {
		if k == "tok" {
			t.Error("raw token stored")
		}
	}
	if err := sessions.Update(ctx, "tok", Session{PrincipalID: "p2", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if s, err := sessions.Get(ctx, "tok"); err != nil || s.PrincipalID != "p2" {
		t.Errorf("get: %+v %v", s, err)
	}
	if err := sessions.Update(ctx, "missing", Session{}); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("update missing: %v", err)
	}
	sessions.now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := sessions.Get(ctx, "tok"); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expired: %v", err)
	}

	states := NewMemoryLoginStateStore()
	if err := states.Put(ctx, "s", LoginState{Nonce: "n", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if ls, err := states.Take(ctx, "s"); err != nil || ls.Nonce != "n" {
		t.Errorf("take: %+v %v", ls, err)
	}
	if _, err := states.Take(ctx, "s"); !errors.Is(err, ErrInvalidState) {
		t.Errorf("second take: %v", err)
	}
	if err := states.Put(ctx, "old", LoginState{ExpiresAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if _, err := states.Take(ctx, "old"); !errors.Is(err, ErrInvalidState) {
		t.Errorf("expired take: %v", err)
	}
}
