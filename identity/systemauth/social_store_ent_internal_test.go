package systemauth

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/oauthclient"
)

func TestEntStoresDeleteExpired(t *testing.T) {
	ctx := context.Background()
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	now := time.Now()
	clock := func() time.Time { return now }
	sessions := NewEntLoginSessionStore(client, withStoreClock(clock), WithCleanupInterval(0))
	states := NewEntLoginStateStore(client, withStoreClock(clock), WithCleanupInterval(0))

	for i, exp := range []time.Duration{-time.Minute, -time.Second, time.Hour} {
		tok := uuid.NewString()
		if err := sessions.Create(ctx, tok, LoginSession{PrincipalID: uuid.New(), CreatedAt: now, ExpiresAt: now.Add(exp)}); err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		if err := states.Put(ctx, tok, oauthclient.StateData{Provider: "github"}, exp); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}

	if n, err := sessions.DeleteExpired(ctx); err != nil || n != 2 {
		t.Fatalf("sessions.DeleteExpired = %d, %v; want 2", n, err)
	}
	if n, err := states.DeleteExpired(ctx); err != nil || n != 2 {
		t.Fatalf("states.DeleteExpired = %d, %v; want 2", n, err)
	}
	if n := client.LoginSession.Query().CountX(ctx); n != 1 {
		t.Fatalf("remaining sessions = %d, want 1", n)
	}
	if n := client.LoginState.Query().CountX(ctx); n != 1 {
		t.Fatalf("remaining states = %d, want 1", n)
	}
}

func TestEntStoresOpportunisticCleanup(t *testing.T) {
	ctx := context.Background()
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})

	now := time.Now()
	sessions := NewEntLoginSessionStore(client, withStoreClock(func() time.Time { return now }), WithCleanupInterval(time.Minute))
	create := func(exp time.Duration) {
		t.Helper()
		if err := sessions.Create(ctx, uuid.NewString(), LoginSession{PrincipalID: uuid.New(), CreatedAt: now, ExpiresAt: now.Add(exp)}); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	create(-time.Second) // first write runs a (no-op) cleanup
	create(time.Hour)    // within the interval: expired row survives
	if n := client.LoginSession.Query().CountX(ctx); n != 2 {
		t.Fatalf("sessions = %d, want 2 before the interval elapses", n)
	}
	now = now.Add(2 * time.Minute)
	create(time.Hour) // interval elapsed: expired row removed
	if n := client.LoginSession.Query().CountX(ctx); n != 2 {
		t.Fatalf("sessions = %d, want 2 after cleanup", n)
	}
}

// newEntSocialServer builds a social login server on Ent storage without
// overriding any social store, so the Ent defaults apply.
func newEntSocialServer(t *testing.T, client *ent.Client, owner uuid.UUID, f *fakeGitHub) *Server {
	t.Helper()
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID:            "spa",
			Type:          "public",
			Name:          "SPA",
			RedirectURIs:  []string{"https://app.example.com/callback"},
			GrantTypes:    []string{"authorization_code"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email"},
		}},
		SocialLogin: &SocialLoginConfig{
			AllowedRedirectOrigins: []string{"https://app.example.com"},
			SkipConsent:            true,
		},
	}, WithStorage(NewEntStorage(client, WithDefaultOwner(owner))), WithSocialConnector(f.connector()))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

// TestSocialLoginEntDefaultsSurviveRestart signs in on one server and
// checks a second server on the same database (a restart or another
// replica) accepts the login session.
func TestSocialLoginEntDefaultsSurviveRestart(t *testing.T) {
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	owner := createTestUser(t, client)
	f := newFakeGitHub(t)

	s1 := newEntSocialServer(t, client, owner, f)
	if _, ok := s1.social.sessions.(*EntLoginSessionStore); !ok {
		t.Fatalf("default session store = %T, want *EntLoginSessionStore", s1.social.sessions)
	}
	if _, ok := s1.social.states.(*EntLoginStateStore); !ok {
		t.Fatalf("default state store = %T, want *EntLoginStateStore", s1.social.states)
	}
	if _, ok := s1.social.consents.(*EntConsentStore); !ok {
		t.Fatalf("default consent store = %T, want *EntConsentStore", s1.social.consents)
	}

	state, stateCookie := startLogin(t, s1, "")
	w := callback(s1, state, stateCookie)
	if w.Code != 302 {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	sess := findCookie(t, w.Result(), LoginCookieName)
	if sess == nil {
		t.Fatal("no session cookie")
	}

	s2 := newEntSocialServer(t, client, owner, f)
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(sess)
	if _, err := s2.social.currentSession(r); err != nil {
		t.Fatalf("session not accepted after restart: %v", err)
	}
}
