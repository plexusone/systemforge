package relyingparty

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestBFFMembershipsFromClaims(t *testing.T) {
	fake := newFakeSystemAuth(t)
	store := NewMemoryPrincipalStore()
	b, err := NewBFF(BFFConfig{Client: fake.client(t), Principals: store, Memberships: ClaimsMemberships})
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

func TestDefaultMembershipSourceIsClaims(t *testing.T) {
	claims := map[string]any{"orgs": []any{map[string]any{
		"id": "o1", "slug": "acme", "name": "Acme", "type": "team", "role": "member",
		"apps": map[string]any{"alpha": "viewer"},
	}}}
	got, err := defaultMembershipSource(nil).Memberships(t.Context(), MembershipQuery{Claims: claims})
	if err != nil || len(got) != 1 {
		t.Fatalf("default source = %+v, %v", got, err)
	}
	m := got[0]
	if m.OrganizationID != "o1" || m.OrganizationSlug != "acme" || m.OrganizationName != "Acme" ||
		m.OrganizationType != "team" || m.Role != "member" || m.Applications["alpha"] != "viewer" {
		t.Errorf("membership = %+v", m)
	}
	// No claims (an API key) means no memberships; so does malformed data.
	for _, c := range []map[string]any{nil, {"orgs": "x"}, {"orgs": []any{"x", map[string]any{"role": "owner"}}}} {
		if got, err := ClaimsMemberships.Memberships(t.Context(), MembershipQuery{Claims: c}); err != nil || len(got) != 0 {
			t.Errorf("claims %v = %+v, %v; want none", c, got, err)
		}
	}
	// The compact access-token form has no slug or name.
	compact := map[string]any{"orgs": []any{map[string]any{"id": "o2", "role": "admin", "apps": map[string]any{"alpha": "admin"}}}}
	got = MembershipsFromClaims(compact)
	if len(got) != 1 || got[0].OrganizationSlug != "" || got[0].Applications["alpha"] != "admin" {
		t.Errorf("compact = %+v", got)
	}
}

// membershipsServer serves a paginated memberships endpoint over the
// fake SystemAuth's client.
func membershipsServer(t *testing.T, total int, token string, calls *int) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		if r.URL.Path != "/userinfo/memberships" || r.Header.Get("Authorization") != "DPoP "+token || r.Header.Get("DPoP") == "" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		start := 0
		if c := r.URL.Query().Get("cursor"); c != "" {
			start, _ = strconv.Atoi(c)
		}
		end := start + 2
		next := strconv.Itoa(end)
		if end >= total {
			end, next = total, ""
		}
		orgs := []map[string]any{}
		for i := start; i < end; i++ {
			orgs = append(orgs, map[string]any{"id": "org-" + strconv.Itoa(i), "slug": "s" + strconv.Itoa(i), "role": "member", "apps": map[string]any{"alpha": "viewer"}})
		}
		writeJSON(w, http.StatusOK, map[string]any{"orgs": orgs, "next_cursor": next})
	}))
	t.Cleanup(srv.Close)
	c := newTestClient(t, "", srv.Client(), Metadata{UserinfoEndpoint: srv.URL + "/userinfo"})
	return c
}

func TestRemoteMemberships(t *testing.T) {
	calls := 0
	c := membershipsServer(t, 5, "tok", &calls)
	src := RemoteMemberships(c)
	got, err := src.Memberships(t.Context(), MembershipQuery{AccessToken: func(context.Context) (string, error) { return "tok", nil }})
	if err != nil || len(got) != 5 || calls != 3 {
		t.Fatalf("got %d memberships in %d calls, %v", len(got), calls, err)
	}
	if got[4].OrganizationID != "org-4" || got[4].Applications["alpha"] != "viewer" {
		t.Errorf("last = %+v", got[4])
	}
	// No token (API key): nothing, and no request.
	calls = 0
	if got, err := src.Memberships(t.Context(), MembershipQuery{}); err != nil || got != nil || calls != 0 {
		t.Errorf("without token: %v %v %d", got, err, calls)
	}
	// A rejected token is an error.
	if _, err := src.Memberships(t.Context(), MembershipQuery{AccessToken: func(context.Context) (string, error) { return "bad", nil }}); err == nil {
		t.Error("rejected token returned no error")
	}
}

func TestClaimsOrRemoteMemberships(t *testing.T) {
	calls := 0
	c := membershipsServer(t, 3, "tok", &calls)
	tok := func(context.Context) (string, error) { return "tok", nil }
	src := ClaimsOrRemoteMemberships(RemoteMemberships(c), nil)
	one := []any{map[string]any{"id": "claim-org", "role": "owner"}}

	// Complete claims are used without a request.
	got, err := src.Memberships(t.Context(), MembershipQuery{Claims: map[string]any{"orgs": one}, AccessToken: tok})
	if err != nil || len(got) != 1 || got[0].OrganizationID != "claim-org" || calls != 0 {
		t.Fatalf("complete claims: %+v %v calls=%d", got, err, calls)
	}
	// Truncated claims, and claims without orgs, go to the endpoint.
	for name, claims := range map[string]map[string]any{
		"truncated": {"orgs": one, "orgs_truncated": true},
		"absent":    {"sub": "x"},
	} {
		calls = 0
		got, err = src.Memberships(t.Context(), MembershipQuery{Claims: claims, AccessToken: tok})
		if err != nil || len(got) != 3 || calls == 0 {
			t.Errorf("%s: %d memberships, %v, calls=%d", name, len(got), err, calls)
		}
	}
	// An unavailable endpoint falls back to the (partial) claims.
	bad := func(context.Context) (string, error) { return "bad", nil }
	got, err = src.Memberships(t.Context(), MembershipQuery{Claims: map[string]any{"orgs": one, "orgs_truncated": true}, AccessToken: bad})
	if err != nil || len(got) != 1 || got[0].OrganizationID != "claim-org" {
		t.Errorf("fallback: %+v %v", got, err)
	}
}

func TestProvisioningMemberships(t *testing.T) {
	claims := map[string]any{"orgs": []any{
		map[string]any{"id": "has", "apps": map[string]any{"alpha": "viewer"}},
		map[string]any{"id": "other-app", "apps": map[string]any{"beta": "viewer"}},
		map[string]any{"id": "none"},
	}}
	var provisioned []string
	fail := true
	src := ProvisioningMemberships(ClaimsMemberships, "alpha", func(_ context.Context, m Membership) error {
		if fail {
			return errors.New("db down")
		}
		provisioned = append(provisioned, m.OrganizationID)
		return nil
	})
	q := MembershipQuery{Claims: claims}
	if _, err := src.Memberships(t.Context(), q); err == nil {
		t.Fatal("hook failure was not returned")
	}
	fail = false
	for range 2 {
		got, err := src.Memberships(t.Context(), q)
		if err != nil || len(got) != 3 {
			t.Fatalf("memberships = %d, %v", len(got), err)
		}
	}
	if len(provisioned) != 1 || provisioned[0] != "has" {
		t.Errorf("provisioned = %v, want [has] once", provisioned)
	}
}
