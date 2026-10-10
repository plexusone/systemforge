package relyingparty

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// logoutToken signs a logout token with the fake's key.
func (f *fakeSystemAuth) logoutToken(typ string, mutate func(gojwt.MapClaims)) string {
	now := time.Now()
	claims := gojwt.MapClaims{
		"iss": f.srv.URL, "aud": testClientID, "sub": f.subject,
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": "jti-" + now.Format(time.RFC3339Nano),
		"events": map[string]any{EventBackchannelLogout: map[string]any{}},
	}
	if mutate != nil {
		mutate(claims)
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.kid
	if typ != "" {
		tok.Header["typ"] = typ
	}
	raw, err := tok.SignedString(f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func postLogout(h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/bff/auth/backchannel-logout", strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestVerifyLogoutTokenRules(t *testing.T) {
	fake := newFakeSystemAuth(t)
	c := fake.client(t)
	ok := fake.logoutToken(LogoutTokenType, nil)
	if _, err := c.VerifyLogoutToken(t.Context(), ok); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	for name, raw := range map[string]string{
		"no typ":             fake.logoutToken("", nil),
		"an ID token's typ":  fake.logoutToken("JWT", nil),
		"another audience":   fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) { m["aud"] = "other" }),
		"another issuer":     fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) { m["iss"] = "https://evil.example.com" }),
		"a nonce":            fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) { m["nonce"] = "n" }),
		"no jti":             fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) { delete(m, "jti") }),
		"no sub or sid":      fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) { delete(m, "sub") }),
		"no events":          fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) { delete(m, "events") }),
		"an unknown event":   fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) { m["events"] = map[string]any{"urn:other": map[string]any{}} }),
		"expired":            fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) { m["exp"] = time.Now().Add(-time.Hour).Unix() }),
		"no expiry":          fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) { delete(m, "exp") }),
		"not a token":        "garbage",
		"an access token":    fake.signedAccessJWT(fake.subject, time.Now()),
		"a tampered payload": ok[:len(ok)-4] + "AAAA",
	} {
		if _, err := c.VerifyLogoutToken(t.Context(), raw); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: %v, want ErrInvalidToken", name, err)
		}
	}
}

func accessChangeEvent(org, reason string) map[string]any {
	ev := map[string]any{"changed_at": time.Now().UTC().Format(time.RFC3339Nano), "reason": reason}
	if org != "" {
		ev["organization_id"] = org
	}
	return ev
}

func TestBackchannelHandlerRecordsAccessChanges(t *testing.T) {
	fake := newFakeSystemAuth(t)
	cache := NewRevocationCache()
	h := BackchannelHandler(cache, fake.client(t))
	issued := time.Now().Add(-time.Minute)

	tok := fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) {
		m["events"] = map[string]any{EventAccessChange: accessChangeEvent("org-1", "membership_removed")}
	})
	if w := postLogout(h, tok); w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("access change: %d %s %q", w.Code, w.Body, w.Header().Get("Cache-Control"))
	}
	if cache.Accept(fake.subject, "org-1", issued) {
		t.Error("the announced change did not reach the cache")
	}
	if !cache.Accept(fake.subject, "org-2", issued) {
		t.Error("an organization-scoped change refused another organization")
	}
	// A change for every organization.
	tok = fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) {
		m["events"] = map[string]any{EventAccessChange: accessChangeEvent("", "deactivated")}
	})
	if w := postLogout(h, tok); w.Code != http.StatusOK {
		t.Fatalf("global change: %d %s", w.Code, w.Body)
	}
	if cache.Accept(fake.subject, "org-2", issued) {
		t.Error("a principal-wide change did not refuse another organization")
	}
}

func TestBackchannelHandlerEndsSessions(t *testing.T) {
	fake := newFakeSystemAuth(t)
	sessions := NewMemorySessionStore()
	ctx := t.Context()
	exp := time.Now().Add(time.Hour)
	for tok, s := range map[string]Session{
		"a": {Subject: fake.subject, SID: "s1", ExpiresAt: exp},
		"b": {Subject: fake.subject, SID: "s2", ExpiresAt: exp},
		"c": {Subject: "someone-else", SID: "s3", ExpiresAt: exp},
	} {
		if err := sessions.Create(ctx, tok, s); err != nil {
			t.Fatal(err)
		}
	}
	h := BackchannelHandler(NewRevocationCache(), fake.client(t), WithBackchannelSessions(sessions))
	alive := func(tok string) bool { _, err := sessions.Get(ctx, tok); return err == nil }

	// A sid ends only that session.
	tok := fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) { m["sid"] = "s1" })
	if w := postLogout(h, tok); w.Code != http.StatusOK {
		t.Fatalf("sid logout: %d %s", w.Code, w.Body)
	}
	if alive("a") || !alive("b") || !alive("c") {
		t.Errorf("after a sid logout: a=%v b=%v c=%v", alive("a"), alive("b"), alive("c"))
	}
	// A sub alone ends every session of the subject, and no one else's.
	if w := postLogout(h, fake.logoutToken(LogoutTokenType, nil)); w.Code != http.StatusOK {
		t.Fatalf("sub logout: %d %s", w.Code, w.Body)
	}
	if alive("b") || !alive("c") {
		t.Errorf("after a sub logout: b=%v c=%v", alive("b"), alive("c"))
	}
}

func TestBackchannelHandlerRefusals(t *testing.T) {
	fake := newFakeSystemAuth(t)
	h := BackchannelHandler(NewRevocationCache(), fake.client(t))
	for name, tc := range map[string]struct {
		w    *httptest.ResponseRecorder
		want int
	}{
		"bad token":  {postLogout(h, "garbage"), http.StatusBadRequest},
		"wrong typ":  {postLogout(h, fake.logoutToken("JWT", nil)), http.StatusBadRequest},
		"empty form": {postLogout(h, ""), http.StatusBadRequest},
	} {
		if tc.w.Code != tc.want {
			t.Errorf("%s: %d, want %d", name, tc.w.Code, tc.want)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", w.Code)
	}

	// A replayed token is refused.
	tok := fake.logoutToken(LogoutTokenType, nil)
	if w := postLogout(h, tok); w.Code != http.StatusOK {
		t.Fatalf("first use: %d", w.Code)
	}
	if w := postLogout(h, tok); w.Code != http.StatusBadRequest {
		t.Errorf("replay: %d, want 400", w.Code)
	}
}

// failingSessions fails deletions so the endpoint answers 500.
type failingSessions struct{ SessionStore }

func (failingSessions) DeleteBySubject(context.Context, string) (int, error) {
	return 0, errors.New("database down")
}

func TestBackchannelHandlerAsksForARetryWhenSessionsCannotBeEnded(t *testing.T) {
	fake := newFakeSystemAuth(t)
	h := BackchannelHandler(NewRevocationCache(), fake.client(t), WithBackchannelSessions(failingSessions{NewMemorySessionStore()}))
	tok := fake.logoutToken(LogoutTokenType, nil)
	if w := postLogout(h, tok); w.Code != http.StatusInternalServerError {
		t.Fatalf("failing store: %d, want 500 so SystemAuth retries", w.Code)
	}
	// The retry of the same token is not mistaken for a replay.
	if w := postLogout(h, tok); w.Code != http.StatusInternalServerError {
		t.Errorf("retry: %d, want the store's failure again, not a replay refusal", w.Code)
	}
}

// TestBFFServesTheBackchannelEndpoint verifies the BFF mounts the receiver
// and wires its sessions and revocation cache.
func TestBFFServesTheBackchannelEndpoint(t *testing.T) {
	fake := newFakeSystemAuth(t)
	cache := NewRevocationCache()
	b, err := NewBFF(BFFConfig{Client: fake.client(t), Principals: NewMemoryPrincipalStore(), Revocation: cache})
	if err != nil {
		t.Fatal(err)
	}
	h := &bffHarness{t: t, fake: fake, store: NewMemoryPrincipalStore(), bff: b}
	sess := h.sessionCookie()

	req := httptest.NewRequest(http.MethodPost, "/bff/auth/backchannel-logout", strings.NewReader(url.Values{"logout_token": {fake.logoutToken(LogoutTokenType, func(m gojwt.MapClaims) {
		m["events"] = map[string]any{EventBackchannelLogout: map[string]any{}, EventAccessChange: accessChangeEvent("", "deactivated")}
	})}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := h.do(req)
	if w.Code != http.StatusOK {
		t.Fatalf("backchannel: %d %s", w.Code, w.Body)
	}
	if _, err := b.cfg.Sessions.Get(t.Context(), sess.Value); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("the session survived a back-channel logout: %v", err)
	}
	if cache.Accept(fake.subject, "", time.Now().Add(-time.Minute)) {
		t.Error("the access change did not reach the BFF's cache")
	}
}
