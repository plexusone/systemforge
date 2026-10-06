package relyingparty

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// claimsMemberships reads memberships from a SystemAuth "orgs" claim, the
// shape a SystemAuth-sourced MembershipSource takes.
var claimsMemberships = MembershipSourceFunc(func(_ context.Context, q MembershipQuery) ([]Membership, error) {
	orgs, _ := q.Claims["orgs"].([]any)
	out := make([]Membership, 0, len(orgs))
	for _, o := range orgs {
		m, _ := o.(map[string]any)
		id, _ := m["id"].(string)
		slug, _ := m["slug"].(string)
		role, _ := m["role"].(string)
		out = append(out, Membership{ID: id, OrganizationID: id, OrganizationSlug: slug, Role: role})
	}
	return out, nil
})

func TestBFFMembershipsFromClaims(t *testing.T) {
	fake := newFakeSystemAuth(t)
	store := NewMemoryPrincipalStore()
	b, err := NewBFF(BFFConfig{Client: fake.client(t), Principals: store, Memberships: claimsMemberships})
	if err != nil {
		t.Fatal(err)
	}
	h := &bffHarness{t: t, fake: fake, store: store, bff: b}
	sess := h.sessionCookie()

	// A local membership row is ignored: SystemAuth claims are the source.
	p, err := store.FindBySubject(t.Context(), fake.subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddMembership(p.ID, Membership{OrganizationID: "local", Role: "owner", JoinedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/bff/api/v1/users/me", nil)
	req.AddCookie(sess)
	w := h.do(req)
	var user User
	if err := json.Unmarshal(w.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}
	if len(user.Memberships) != 1 || user.Memberships[0].OrganizationSlug != "nine" || user.Memberships[0].Role != "admin" {
		t.Errorf("memberships = %+v", user.Memberships)
	}

	stored, err := b.cfg.Sessions.Get(t.Context(), sess.Value)
	if err != nil {
		t.Fatal(err)
	}
	if stored.SID != "sa-session-1" || stored.Claims["email"] != "octo@example.com" {
		t.Errorf("session sid/claims: %q %v", stored.SID, stored.Claims)
	}
}

func TestSessionStoreDeleteBySubjectAndSID(t *testing.T) {
	ctx := t.Context()
	s := NewMemorySessionStore()
	exp := time.Now().Add(time.Hour)
	for tok, sess := range map[string]Session{
		"a": {Subject: "u1", SID: "s1", ExpiresAt: exp},
		"b": {Subject: "u1", SID: "s2", ExpiresAt: exp},
		"c": {Subject: "u2", SID: "s3", ExpiresAt: exp},
	} {
		if err := s.Create(ctx, tok, sess); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.DeleteBySID(ctx, "s3"); err != nil || n != 1 {
		t.Errorf("DeleteBySID = %d %v", n, err)
	}
	if n, err := s.DeleteBySubject(ctx, "u1"); err != nil || n != 2 {
		t.Errorf("DeleteBySubject = %d %v", n, err)
	}
	if n, err := s.DeleteBySubject(ctx, ""); err != nil || n != 0 {
		t.Errorf("empty subject deleted %d %v", n, err)
	}
	if len(s.sessions) != 0 {
		t.Errorf("sessions left: %d", len(s.sessions))
	}
}

func TestDefaultMembershipSource(t *testing.T) {
	type bare struct{ PrincipalStore }
	if got, err := defaultMembershipSource(nil, bare{}).Memberships(t.Context(), MembershipQuery{Principal: &Principal{ID: "x"}}); err != nil || got != nil {
		t.Errorf("store without lister: %v %v", got, err)
	}
}
