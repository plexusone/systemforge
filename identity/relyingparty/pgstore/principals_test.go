package pgstore

import (
	"errors"
	"testing"

	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/relyingparty/storetest"
)

func TestPrincipalStoreConformance(t *testing.T) {
	storetest.PrincipalStore(t, func(t *testing.T) relyingparty.PrincipalStore {
		s, err := NewPrincipalStore(openDB(t))
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestPrincipalStoreActiveAndDelete(t *testing.T) {
	ctx := t.Context()
	s, err := NewPrincipalStore(openDB(t))
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.CreatePrincipal(ctx, storetest.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetActive(ctx, p.ID, false); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPrincipal(ctx, p.ID)
	if err != nil || got.Active {
		t.Errorf("after disabling: %+v %v", got, err)
	}
	// relyingparty refuses the inactive principal at sign-in.
	id := storetest.Identity()
	id.Subject = p.SFPrincipalID
	if _, err := relyingparty.ResolvePrincipal(ctx, s, id, got.CreatedAt); !errors.Is(err, relyingparty.ErrPrincipalInactive) {
		t.Errorf("inactive sign-in: %v", err)
	}
	if err := s.Delete(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPrincipal(ctx, p.ID); !errors.Is(err, relyingparty.ErrPrincipalNotFound) {
		t.Errorf("after delete: %v", err)
	}
	for name, err := range map[string]error{
		"set active": s.SetActive(ctx, p.ID, true),
		"delete":     s.Delete(ctx, p.ID),
		"bad id":     s.SetActive(ctx, "nope", true),
	} {
		if !errors.Is(err, relyingparty.ErrPrincipalNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewPrincipalStoreNeedsADatabase(t *testing.T) {
	if _, err := NewPrincipalStore(nil); err == nil {
		t.Error("nil database accepted")
	}
}
