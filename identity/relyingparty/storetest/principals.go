package storetest

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/relyingparty"
)

// Identity returns a verified identity with a fresh subject and email.
func Identity() relyingparty.VerifiedIdentity {
	sub := uuid.NewString()
	return relyingparty.VerifiedIdentity{
		Subject: sub, Email: "user-" + sub[:8] + "@example.com", EmailVerified: true,
		Name: "User " + sub[:8], Picture: "https://example.com/" + sub[:8] + ".png",
	}
}

// PrincipalStore runs the conformance suite for a relyingparty.PrincipalStore.
// newStore must return an empty store.
func PrincipalStore(t *testing.T, newStore func(t *testing.T) relyingparty.PrincipalStore) {
	t.Run("CreateAndFind", func(t *testing.T) { principalCreateAndFind(t, newStore(t)) })
	t.Run("NotFound", func(t *testing.T) { principalNotFound(t, newStore(t)) })
	t.Run("Conflicts", func(t *testing.T) { principalConflicts(t, newStore(t)) })
	t.Run("Managed", func(t *testing.T) { principalManaged(t, newStore(t)) })
	t.Run("Service", func(t *testing.T) { principalService(t, newStore(t)) })
	t.Run("LinkSubject", func(t *testing.T) { principalLinkSubject(t, newStore(t)) })
	t.Run("RecordLogin", func(t *testing.T) { principalRecordLogin(t, newStore(t)) })
}

func principalCreateAndFind(t *testing.T, s relyingparty.PrincipalStore) {
	ctx := t.Context()
	id := Identity()
	p, err := s.CreatePrincipal(ctx, id)
	if err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	if p.ID == "" || p.SFPrincipalID != id.Subject || p.Email != id.Email || !p.EmailVerified ||
		!p.Active || p.Managed || p.Type != "human" || p.Name != id.Name || p.AvatarURL != id.Picture {
		t.Errorf("created: %+v", p)
	}
	for name, find := range map[string]func() (*relyingparty.Principal, error){
		"subject": func() (*relyingparty.Principal, error) { return s.FindBySubject(ctx, id.Subject) },
		"email":   func() (*relyingparty.Principal, error) { return s.FindByEmail(ctx, id.Email) },
		"upper":   func() (*relyingparty.Principal, error) { return s.FindByEmail(ctx, upper(id.Email)) },
		"id":      func() (*relyingparty.Principal, error) { return s.GetPrincipal(ctx, p.ID) },
	} {
		got, err := find()
		if err != nil || got.ID != p.ID || got.SFPrincipalID != id.Subject {
			t.Errorf("find by %s: %+v %v", name, got, err)
		}
	}

	// The name defaults to the email.
	noName := Identity()
	noName.Name = ""
	p, err = s.CreatePrincipal(ctx, noName)
	if err != nil || p.Name != noName.Email {
		t.Errorf("default name: %+v %v", p, err)
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

func principalNotFound(t *testing.T, s relyingparty.PrincipalStore) {
	ctx := t.Context()
	checks := map[string]func() error{
		"subject":   func() error { _, err := s.FindBySubject(ctx, uuid.NewString()); return err },
		"email":     func() error { _, err := s.FindByEmail(ctx, "nobody@example.com"); return err },
		"no email":  func() error { _, err := s.FindByEmail(ctx, ""); return err },
		"id":        func() error { _, err := s.GetPrincipal(ctx, uuid.NewString()); return err },
		"bad id":    func() error { _, err := s.GetPrincipal(ctx, "not-an-id"); return err },
		"link":      func() error { return s.LinkSubject(ctx, uuid.NewString(), uuid.NewString()) },
		"login":     func() error { return s.RecordLogin(ctx, uuid.NewString(), Identity(), time.Now()) },
		"bad login": func() error { return s.RecordLogin(ctx, "not-an-id", Identity(), time.Now()) },
	}
	for name, check := range checks {
		if err := check(); !errors.Is(err, relyingparty.ErrPrincipalNotFound) {
			t.Errorf("%s: %v, want ErrPrincipalNotFound", name, err)
		}
	}
}

func principalConflicts(t *testing.T, s relyingparty.PrincipalStore) {
	ctx := t.Context()
	id := Identity()
	if _, err := s.CreatePrincipal(ctx, id); err != nil {
		t.Fatal(err)
	}
	sameSubject := Identity()
	sameSubject.Subject = id.Subject
	if _, err := s.CreatePrincipal(ctx, sameSubject); !errors.Is(err, relyingparty.ErrSubjectLinked) {
		t.Errorf("same subject: %v", err)
	}
	sameEmail := Identity()
	sameEmail.Email = upper(id.Email)
	if _, err := s.CreatePrincipal(ctx, sameEmail); !errors.Is(err, relyingparty.ErrEmailConflict) {
		t.Errorf("same email: %v", err)
	}
	// A refused create leaves nothing behind.
	if _, err := s.FindBySubject(ctx, sameEmail.Subject); !errors.Is(err, relyingparty.ErrPrincipalNotFound) {
		t.Errorf("refused create stored: %v", err)
	}
}

func principalManaged(t *testing.T, s relyingparty.PrincipalStore) {
	ctx := t.Context()
	for range 2 {
		id := Identity()
		id.Email, id.EmailVerified, id.Managed = "", false, true
		p, err := s.CreatePrincipal(ctx, id)
		if err != nil {
			t.Fatalf("managed without email: %v", err)
		}
		if !p.Managed || p.Email != "" || p.EmailVerified || !p.Active {
			t.Errorf("managed: %+v", p)
		}
		got, err := s.FindBySubject(ctx, id.Subject)
		if err != nil || !got.Managed {
			t.Errorf("find managed: %+v %v", got, err)
		}
	}
}

func principalLinkSubject(t *testing.T, s relyingparty.PrincipalStore) {
	ctx := t.Context()
	a, err := s.CreatePrincipal(ctx, Identity())
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreatePrincipal(ctx, Identity())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.LinkSubject(ctx, a.ID, b.SFPrincipalID); !errors.Is(err, relyingparty.ErrSubjectLinked) {
		t.Errorf("subject linked elsewhere: %v", err)
	}
	fresh := uuid.NewString()
	if err := s.LinkSubject(ctx, a.ID, fresh); err != nil {
		t.Fatalf("link: %v", err)
	}
	got, err := s.FindBySubject(ctx, fresh)
	if err != nil || got.ID != a.ID {
		t.Errorf("after link: %+v %v", got, err)
	}
}

func principalRecordLogin(t *testing.T, s relyingparty.PrincipalStore) {
	ctx := t.Context()
	id := Identity()
	p, err := s.CreatePrincipal(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	id.Name, id.Picture = "Renamed", "https://example.com/new.png"
	if err := s.RecordLogin(ctx, p.ID, id, time.Now()); err != nil {
		t.Fatalf("RecordLogin: %v", err)
	}
	got, err := s.GetPrincipal(ctx, p.ID)
	if err != nil || got.Name != "Renamed" || got.AvatarURL != id.Picture {
		t.Errorf("after login: %+v %v", got, err)
	}
	// Empty profile fields keep the stored ones.
	if err := s.RecordLogin(ctx, p.ID, relyingparty.VerifiedIdentity{Subject: id.Subject}, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetPrincipal(ctx, p.ID)
	if err != nil || got.Name != "Renamed" || got.AvatarURL != id.Picture {
		t.Errorf("empty profile: %+v %v", got, err)
	}
}

func principalService(t *testing.T, s relyingparty.PrincipalStore) {
	ctx := t.Context()
	for range 2 {
		sub := uuid.NewString()
		p, err := s.CreatePrincipal(ctx, relyingparty.VerifiedIdentity{Subject: sub, Name: "ci-publisher", Service: true})
		if err != nil {
			t.Fatalf("service identity: %v", err)
		}
		if p.Type != "service" || p.Email != "" || p.EmailVerified || p.Managed || !p.Active || p.Name != "ci-publisher" {
			t.Errorf("service: %+v", p)
		}
		got, err := s.FindBySubject(ctx, sub)
		if err != nil || got.Type != "service" {
			t.Errorf("find service: %+v %v", got, err)
		}
	}
}
