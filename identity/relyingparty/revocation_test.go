package relyingparty

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestRevocationCacheAcceptRule(t *testing.T) {
	clk := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	c := NewRevocationCache(WithClock(clk.now))
	changed := clk.now()
	if c.Margin() != 30*time.Second {
		t.Errorf("default margin = %v, want 30s", c.Margin())
	}

	// No entry: everything is accepted, even a token without iat.
	if !c.Accept("p", "", time.Time{}) || !c.Accept("p", "org", changed.Add(-time.Hour)) {
		t.Error("tokens refused with nothing recorded")
	}

	c.Record(AccessChange{PrincipalID: "p", ChangedAt: changed, Reason: "deactivated"})
	for name, tc := range map[string]struct {
		iat  time.Time
		want bool
	}{
		"before the change":          {changed.Add(-time.Second), false},
		"at the change":              {changed, false},
		"inside the margin":          {changed.Add(29 * time.Second), false},
		"exactly at change + margin": {changed.Add(30 * time.Second), true},
		"after the margin":           {changed.Add(time.Minute), true},
		"no iat":                     {time.Time{}, false},
	} {
		if got := c.Accept("p", "", tc.iat); got != tc.want {
			t.Errorf("%s: Accept = %v, want %v", name, got, tc.want)
		}
	}
	if !c.Accept("other", "", changed.Add(-time.Hour)) {
		t.Error("another principal was refused")
	}
	if got := c.ValidFrom("p", ""); !got.Equal(changed.Add(30 * time.Second)) {
		t.Errorf("ValidFrom = %v", got)
	}
	if !c.ValidFrom("other", "").IsZero() {
		t.Error("ValidFrom for an unaffected principal is not zero")
	}
}

func TestRevocationCacheOrganizationScope(t *testing.T) {
	clk := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	c := NewRevocationCache(WithClock(clk.now))
	changed := clk.now()
	old := changed.Add(-time.Minute)

	c.Record(AccessChange{PrincipalID: "p", OrganizationID: "acme", ChangedAt: changed, Reason: "membership_removed"})
	if c.Accept("p", "acme", old) {
		t.Error("old token accepted in the affected organization")
	}
	if !c.Accept("p", "other", old) {
		t.Error("old token refused in an unaffected organization")
	}
	// Without a known organization every change applies.
	if c.Accept("p", "", old) {
		t.Error("old token accepted with no organization named")
	}

	// A principal-wide change applies to every organization.
	c.Record(AccessChange{PrincipalID: "p", ChangedAt: changed.Add(time.Second), Reason: "deactivated"})
	if c.Accept("p", "other", old) {
		t.Error("old token accepted after a principal-wide change")
	}
}

func TestRevocationCacheRecordIsIdempotentAndOrderFree(t *testing.T) {
	clk := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	c := NewRevocationCache(WithClock(clk.now))
	t1, t2 := clk.now(), clk.now().Add(5*time.Second)
	c.Record(AccessChange{PrincipalID: "p", ChangedAt: t2})
	c.Record(AccessChange{PrincipalID: "p", ChangedAt: t1}) // late, earlier
	c.Record(AccessChange{PrincipalID: "p", ChangedAt: t2})
	if got := c.ChangedAt("p", ""); !got.Equal(t2) {
		t.Errorf("ChangedAt = %v, want the latest %v", got, t2)
	}
	// Garbage is ignored.
	c.Record(AccessChange{ChangedAt: t1})
	c.Record(AccessChange{PrincipalID: "q"})
	if c.Len() != 1 {
		t.Errorf("Len = %d, want 1", c.Len())
	}
}

func TestRevocationCacheMarginFloorAndOptions(t *testing.T) {
	if got := NewRevocationCache(WithSkewMargin(time.Second)).Margin(); got != MinSkewMargin {
		t.Errorf("margin below the floor = %v, want %v", got, MinSkewMargin)
	}
	if got := NewRevocationCache(WithSkewMargin(45 * time.Second)).Margin(); got != 45*time.Second {
		t.Errorf("margin = %v, want 45s", got)
	}
}

// TestRevocationCacheEntriesExpire verifies that an entry is dropped at
// changed_at + max lifetime + margin, and not before.
func TestRevocationCacheEntriesExpire(t *testing.T) {
	clk := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	c := NewRevocationCache(WithClock(clk.now), WithMaxTokenLifetime(10*time.Minute), WithSkewMargin(20*time.Second))
	changed := clk.now()
	c.Record(AccessChange{PrincipalID: "p", ChangedAt: changed})
	old := changed.Add(-time.Second)

	clk.advance(10*time.Minute + 20*time.Second) // exactly the retention
	if c.Accept("p", "", old) {
		t.Error("entry dropped at the retention boundary; a token could still be valid at a skewed verifier")
	}
	clk.advance(time.Second)
	if !c.Accept("p", "", old) {
		t.Error("entry kept past changed_at + lifetime + margin")
	}
	c.Sweep()
	if c.Len() != 0 {
		t.Errorf("Len after sweep = %d, want 0", c.Len())
	}

	// A change already past its retention is not stored.
	c.Record(AccessChange{PrincipalID: "p", ChangedAt: changed})
	if c.Len() != 0 {
		t.Errorf("expired change stored: Len = %d", c.Len())
	}
}

// TestRevocationCacheIsBounded verifies that Record sweeps, so the cache
// holds only the changes of the last lifetime however many it has seen.
func TestRevocationCacheIsBounded(t *testing.T) {
	clk := &clock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	c := NewRevocationCache(WithClock(clk.now), WithMaxTokenLifetime(time.Minute))
	for i := range 200 {
		c.Record(AccessChange{PrincipalID: "p" + strconv.Itoa(i), OrganizationID: "o", ChangedAt: clk.now()})
		clk.advance(10 * time.Second)
	}
	// Retention is a minute plus the 30 s margin: 9 changes at 10 s apart.
	if n := c.Len(); n > 10 {
		t.Errorf("Len = %d; the cache is not bounded by the retention", n)
	}
}

func TestRevocationCacheConcurrent(t *testing.T) {
	c := NewRevocationCache()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := range 200 {
				c.Record(AccessChange{PrincipalID: "p" + strconv.Itoa(j%5), OrganizationID: strconv.Itoa(i), ChangedAt: time.Now()})
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				c.Accept("p1", "", time.Now())
				c.Sweep()
			}
		}()
	}
	wg.Wait()
}

func TestRecordChangeAdapter(t *testing.T) {
	c := NewRevocationCache()
	now := time.Now()
	c.RecordChange("p", "org", now, "org_role_changed")
	if got := c.ChangedAt("p", "org"); !got.Equal(now) {
		t.Errorf("ChangedAt = %v, want %v", got, now)
	}
}

// signedAccessJWT returns a SystemAuth-style access token issued at iat.
func (f *fakeSystemAuth) signedAccessJWT(sub string, iat time.Time) string {
	return f.sign(gojwt.MapClaims{
		"iss": f.srv.URL, "sub": sub, "client_id": testClientID, "scp": []string{"things:read"},
		"exp": iat.Add(time.Hour).Unix(), "iat": iat.Unix(), "jti": fmt.Sprint(iat.UnixNano()),
	})
}

// TestBearerMiddlewareRefusesTokensIssuedBeforeAChange verifies the ADR-010
// acceptance rule at the middleware: a token issued before a change (or
// inside the margin) is answered "token expired", and one issued after the
// margin is accepted.
func TestBearerMiddlewareRefusesTokensIssuedBeforeAChange(t *testing.T) {
	fake := newFakeSystemAuth(t)
	store := NewMemoryPrincipalStore()
	if _, err := store.AddPrincipal(Principal{Email: "octo@example.com", EmailVerified: true, Active: true, SFPrincipalID: fake.subject}); err != nil {
		t.Fatal(err)
	}
	cache := NewRevocationCache()
	org := uuid.NewString()
	cfg := BearerConfig{Tokens: fake.client(t), Principals: store, Revocation: cache, AllowBearerTokens: true,
		Organization: func(r *http.Request) string { return r.Header.Get("X-Org") }}
	now := time.Now()

	// Nothing recorded: accepted.
	if w, _ := runBearer(t, cfg, withBearer(fake.signedAccessJWT(fake.subject, now.Add(-time.Minute)))); w.Code != http.StatusOK {
		t.Fatalf("before any change: %d", w.Code)
	}

	sink := cache // the same instance SystemAuth would record into
	sink.Record(AccessChange{PrincipalID: fake.subject, OrganizationID: org, ChangedAt: now, Reason: "membership_removed"})
	inOrg := func(r *http.Request) { r.Header.Set("X-Org", org) }
	with := func(token string, extra func(*http.Request)) func(*http.Request) {
		return func(r *http.Request) {
			withBearer(token)(r)
			if extra != nil {
				extra(r)
			}
		}
	}

	w, _ := runBearer(t, cfg, with(fake.signedAccessJWT(fake.subject, now.Add(-time.Minute)), inOrg))
	challenge := w.Header().Get("WWW-Authenticate")
	if w.Code != http.StatusUnauthorized || !strings.Contains(challenge, `error="invalid_token"`) || !strings.Contains(challenge, `error_description="token expired"`) {
		t.Errorf("token issued before the change: %d %q", w.Code, challenge)
	}
	if w, _ := runBearer(t, cfg, with(fake.signedAccessJWT(fake.subject, now.Add(10*time.Second)), inOrg)); w.Code != http.StatusUnauthorized {
		t.Errorf("token issued inside the margin: %d", w.Code)
	}
	if w, _ := runBearer(t, cfg, with(fake.signedAccessJWT(fake.subject, now.Add(31*time.Second)), inOrg)); w.Code != http.StatusOK {
		t.Errorf("token issued after the margin: %d", w.Code)
	}
	// Another organization is not affected by an organization-scoped change.
	other := func(r *http.Request) { r.Header.Set("X-Org", uuid.NewString()) }
	if w, _ := runBearer(t, cfg, with(fake.signedAccessJWT(fake.subject, now.Add(-time.Minute)), other)); w.Code != http.StatusOK {
		t.Errorf("unaffected organization: %d", w.Code)
	}

	// The same answer reaches the protocol-neutral authenticator.
	ra := NewRequestAuthenticator(cfg)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	withBearer(fake.signedAccessJWT(fake.subject, now.Add(-time.Minute)))(req)
	inOrg(req)
	_, err := ra.Authenticate(req)
	if err == nil || !strings.Contains(err.Error(), "token expired") {
		t.Errorf("RequestAuthenticator: %v", err)
	}
}

// TestBFFRefreshesClaimsAfterAnAccessChange verifies that a recorded change
// makes the BFF refresh the session's tokens and claims instead of ending
// the session, once; and that a refresh SystemAuth rejects ends it.
func TestBFFRefreshesClaimsAfterAnAccessChange(t *testing.T) {
	fake := newFakeSystemAuth(t)
	store := NewMemoryPrincipalStore()
	cache := NewRevocationCache()
	b, err := NewBFF(BFFConfig{Client: fake.client(t), Principals: store, Revocation: cache})
	if err != nil {
		t.Fatal(err)
	}
	h := &bffHarness{t: t, fake: fake, store: store, bff: b}
	sess := h.sessionCookie()

	memberships := func() ([]UserMembership, bool) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/bff/api/v1/users/me", nil)
		req.AddCookie(sess)
		w := h.do(req)
		if w.Code != http.StatusOK {
			return nil, false
		}
		var u User
		if err := json.Unmarshal(w.Body.Bytes(), &u); err != nil {
			t.Fatal(err)
		}
		return u.Memberships, true
	}
	issued := func() int {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		return fake.n
	}

	if ms, ok := memberships(); !ok || len(ms) != 1 || ms[0].OrganizationID != "org-9" {
		t.Fatalf("before the change: %+v %v", ms, ok)
	}
	before := issued()
	if ms, _ := memberships(); len(ms) != 1 || issued() != before {
		t.Fatalf("an unchanged session refreshed: %d tokens issued", issued()-before)
	}

	// The principal is removed from org-9: SystemAuth now answers without it.
	fake.mu.Lock()
	fake.userinfo = map[string]any{"sub": fake.subject, "email": fake.email, "email_verified": true, "name": fake.name}
	fake.mu.Unlock()
	cache.Record(AccessChange{PrincipalID: fake.subject, OrganizationID: "org-9", ChangedAt: time.Now(), Reason: "membership_removed"})

	ms, ok := memberships()
	if !ok || len(ms) != 0 {
		t.Fatalf("after the change: %+v %v; want a live session with no memberships", ms, ok)
	}
	if issued() == before {
		t.Error("the session was not refreshed")
	}
	after := issued()
	if _, ok := memberships(); !ok || issued() != after {
		t.Errorf("one change refreshed again: %d tokens issued", issued()-after)
	}

	// A later change meets a refresh token SystemAuth refuses (deactivation):
	// the session ends.
	fake.mu.Lock()
	for rt := range fake.refresh {
		fake.refresh[rt] = false
	}
	fake.mu.Unlock()
	cache.Record(AccessChange{PrincipalID: fake.subject, ChangedAt: time.Now().Add(time.Second), Reason: "deactivated"})
	if _, ok := memberships(); ok {
		t.Error("the session survived a refused refresh")
	}
}
