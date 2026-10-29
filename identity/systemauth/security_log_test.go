package systemauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v3"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/serviceaccount"
)

// logCapture is a slog handler that keeps every record three ways: as
// slog's text handler and JSON handler write it, and as the %+v of every
// attribute value, walked recursively through groups and LogValuers.
type logCapture struct {
	shared *logCaptureStore
	text   slog.Handler
	json   slog.Handler
	attrs  []slog.Attr
}

type logCaptureStore struct {
	mu     sync.Mutex
	text   bytes.Buffer
	json   bytes.Buffer
	values []string
}

func newLogCapture() *logCapture {
	st := &logCaptureStore{}
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	return &logCapture{
		shared: st,
		text:   slog.NewTextHandler(lockedWriter{st, &st.text}, opts),
		json:   slog.NewJSONHandler(lockedWriter{st, &st.json}, opts),
	}
}

type lockedWriter struct {
	st  *logCaptureStore
	buf *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.st.mu.Lock()
	defer w.st.mu.Unlock()
	return w.buf.Write(p)
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(ctx context.Context, r slog.Record) error {
	var vals []string
	vals = append(vals, r.Message)
	for _, a := range c.attrs {
		vals = walkAttr(vals, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		vals = walkAttr(vals, a)
		return true
	})
	c.shared.mu.Lock()
	c.shared.values = append(c.shared.values, vals...)
	c.shared.mu.Unlock()
	if err := c.text.Handle(ctx, r.Clone()); err != nil {
		return err
	}
	return c.json.Handle(ctx, r.Clone())
}

func walkAttr(out []string, a slog.Attr) []string {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		for _, g := range v.Group() {
			out = walkAttr(out, g)
		}
		return out
	}
	return append(out, a.Key+"="+fmt.Sprintf("%+v", v.Any()))
}

func (c *logCapture) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &logCapture{shared: c.shared, text: c.text.WithAttrs(attrs), json: c.json.WithAttrs(attrs), attrs: append(append([]slog.Attr{}, c.attrs...), attrs...)}
}

func (c *logCapture) WithGroup(name string) slog.Handler {
	return &logCapture{shared: c.shared, text: c.text.WithGroup(name), json: c.json.WithGroup(name), attrs: c.attrs}
}

// eventCapture is an audit emitter keeping every event.
type eventCapture struct {
	mu     sync.Mutex
	events []audit.Event
}

func (e *eventCapture) Emit(_ context.Context, ev *audit.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, *ev)
	return nil
}

func (e *eventCapture) find(eventType, outcome string) []audit.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []audit.Event
	for _, ev := range e.events {
		if ev.EventType == eventType && (outcome == "" || ev.Outcome == outcome) {
			out = append(out, ev)
		}
	}
	return out
}

// secretSet collects the secrets a test flow handles.
type secretSet map[string]string

func (s secretSet) add(what, v string) {
	if v != "" {
		s[v] = what
	}
}

func (s secretSet) addTokens(body map[string]any) {
	for _, k := range []string{"access_token", "refresh_token", "id_token"} {
		if v, ok := body[k].(string); ok {
			s.add(k, v)
		}
	}
}

// assertNoSecrets fails when any secret appears in any log record, in any
// rendering, or in any security event.
func assertNoSecrets(t *testing.T, logs *logCapture, events *eventCapture, secrets secretSet) {
	t.Helper()
	logs.shared.mu.Lock()
	text, js := logs.shared.text.String(), logs.shared.json.String()
	values := strings.Join(logs.shared.values, "\n")
	logs.shared.mu.Unlock()
	if text == "" {
		t.Fatal("nothing was logged")
	}
	events.mu.Lock()
	evJSON, err := json.Marshal(events.events)
	events.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for secret, what := range secrets {
		for name, out := range map[string]string{"text log": text, "JSON log": js, "log attributes": values, "security events": string(evJSON)} {
			if strings.Contains(out, secret) {
				t.Errorf("%s leaks the %s", name, what)
			}
		}
	}
	if strings.Contains(text, ".go:") {
		t.Errorf("text log carries a stack trace:\n%s", text)
	}
}

const (
	logTestHMACSecret   = "log-test-hmac-secret-0123456789abcdefghijkl" //nolint:gosec // G101: test fixture
	logTestClientSecret = "log-test-client-secret-9876543210"           //nolint:gosec // G101: test fixture
	logTestWrongSecret  = "log-test-wrong-secret-1357924680"            //nolint:gosec // G101: test fixture
)

// postTokenWithProof posts form to the token endpoint with a fresh DPoP
// proof, recording the proof as a secret.
func postTokenWithProof(t *testing.T, s *Server, form url.Values, secrets secretSet) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "log-test")
	req.RemoteAddr = "203.0.113.9:5000"
	proof := proofFor(t, testDPoPKey(t), http.MethodPost, testIssuer+"/oauth/token", "")
	secrets.add("DPoP proof", proof)
	req.Header.Set("DPoP", proof)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	body := map[string]any{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("token response not JSON (%d): %s", w.Code, w.Body.String())
	}
	secrets.addTokens(body)
	return w.Code, body
}

// TestLogsCarryNoSecrets runs social login, the authorization code flow
// with PKCE, refresh, refused and replayed token requests, client
// credentials, revocation and logout through SystemAuth logging at debug
// level, and checks that no token, code, verifier, secret, proof or session
// cookie reaches a log record or a security event.
func TestLogsCarryNoSecrets(t *testing.T) {
	logs := newLogCapture()
	events := &eventCapture{}
	f := newFakeGitHub(t)
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Tokens: TokenConfig{HMACSecret: logTestHMACSecret},
		Clients: []ClientConfig{{
			ID: "spa", Type: "public", Name: "Example App",
			RedirectURIs:  []string{testRPCB},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}, {
			ID: "svc", Type: "confidential", Name: "Service", Secret: logTestClientSecret,
			GrantTypes: []string{"client_credentials"}, Scopes: []string{"read"},
		}},
		SocialLogin: &SocialLoginConfig{
			AllowedRedirectOrigins: []string{"https://app.example.com"},
			SkipConsent:            true,
		},
	}, WithSocialConnector(f.connector()), WithLogger(slog.New(logs)), WithAuditEmitter(events))
	if err != nil {
		t.Fatal(err)
	}
	secrets := secretSet{}
	secrets.add("HMAC secret", logTestHMACSecret)
	secrets.add("client secret", logTestClientSecret)
	secrets.add("wrong client secret", logTestWrongSecret)
	secrets.add("PKCE verifier", testVerifier)
	secrets.add("upstream client secret", "gh-secret")
	secrets.add("upstream access token", "gh-token")
	secrets.add("upstream authorization code", "upstream-code")

	// Social login: the login state and the session cookie.
	state, stateCookie := startLogin(t, s, "")
	secrets.add("login state", state)
	secrets.add("login state cookie", stateCookie.Value)
	w := callback(s, state, stateCookie)
	if w.Code != http.StatusFound {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	sess := findCookie(t, w.Result(), LoginCookieName)
	if sess == nil {
		t.Fatal("no session cookie")
	}
	secrets.add("session cookie", sess.Value)
	// A refused callback: the state was used.
	if w := callback(s, state, stateCookie); w.Code != http.StatusBadRequest {
		t.Errorf("replayed login state: %d", w.Code)
	}

	// Authorization code with PKCE.
	code := authorizeCode(t, s, "openid email offline_access", withCookie(sess))
	secrets.add("authorization code", code)
	form := codeForm(code)
	form.Set("client_id", "spa")
	status, tokens := postTokenWithProof(t, s, form, secrets)
	if status != http.StatusOK {
		t.Fatalf("code exchange: %d %v", status, tokens)
	}

	// The same code again is a replay.
	if status, body := postTokenWithProof(t, s, form, secrets); status == http.StatusOK {
		t.Fatalf("replayed code accepted: %v", body)
	}
	// An unknown code is refused.
	bad := codeForm("not-a-real-code." + code)
	bad.Set("client_id", "spa")
	secrets.add("forged authorization code", bad.Get("code"))
	if status, body := postTokenWithProof(t, s, bad, secrets); status == http.StatusOK {
		t.Fatalf("forged code accepted: %v", body)
	}

	// The code replay revoked the family, so a fresh login session and
	// code give the tokens to refresh.
	code2 := authorizeCode(t, s, "openid email offline_access", withCookie(sess))
	secrets.add("authorization code", code2)
	form2 := codeForm(code2)
	form2.Set("client_id", "spa")
	status, second := postTokenWithProof(t, s, form2, secrets)
	if status != http.StatusOK {
		t.Fatalf("second code exchange: %d %v", status, second)
	}
	rt1, _ := second["refresh_token"].(string)
	at1, _ := second["access_token"].(string)
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt1}, "client_id": {"spa"}}
	if status, body := postTokenWithProof(t, s, refreshForm, secrets); status != http.StatusOK {
		t.Fatalf("refresh: %d %v", status, body)
	}
	// Reusing the rotated refresh token is detected.
	if status, body := postTokenWithProof(t, s, refreshForm, secrets); status == http.StatusOK {
		t.Fatalf("reused refresh token accepted: %v", body)
	}

	// Client credentials, with the right and a wrong secret.
	cc := url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {logTestClientSecret}, "scope": {"read"}}
	if status, body := postTokenWithProof(t, s, cc, secrets); status != http.StatusOK {
		t.Fatalf("client credentials: %d %v", status, body)
	}
	cc.Set("client_secret", logTestWrongSecret)
	if status, body := postTokenWithProof(t, s, cc, secrets); status == http.StatusOK {
		t.Fatalf("wrong client secret accepted: %v", body)
	}

	// Revocation.
	rev := httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(url.Values{"token": {at1}, "token_type_hint": {"access_token"}, "client_id": {"spa"}}.Encode()))
	rev.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	s.ServeHTTP(rw, rev)
	if rw.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", rw.Code, rw.Body.String())
	}

	// A protected request with a bad token (debug log).
	api := httptest.NewRequest(http.MethodGet, UserInfoPath, nil)
	api.Header.Set("Authorization", "Bearer "+at1)
	s.ServeHTTP(httptest.NewRecorder(), api)

	// Logout.
	if w := postForm(s, LogoutPath, "https://app.example.com", url.Values{}, sess); w.Code != http.StatusSeeOther {
		t.Fatalf("logout: %d", w.Code)
	}

	assertNoSecrets(t, logs, events, secrets)

	for _, want := range []struct{ eventType, outcome string }{
		{EventSigningKeyLoaded, audit.OutcomeSuccess},
		{EventSignIn, audit.OutcomeSuccess},
		{EventSignIn, audit.OutcomeFailure},
		{EventAuthorizationCodeReuse, audit.OutcomeFailure},
		{EventRefreshTokenReuse, audit.OutcomeFailure},
		{EventTokenRefused, audit.OutcomeFailure},
		{EventTokenRevoked, audit.OutcomeSuccess},
		{EventSignOut, audit.OutcomeSuccess},
	} {
		if len(events.find(want.eventType, want.outcome)) == 0 {
			t.Errorf("no %s event with outcome %s", want.eventType, want.outcome)
		}
	}
	// Request-scoped events carry the request ID and the client address.
	for _, ev := range events.find(EventTokenRefused, "") {
		if ev.Context.RequestID == "" || ev.Context.ClientIP != "203.0.113.9" || ev.Context.UserAgent != "log-test" {
			t.Errorf("token refusal context: %+v", ev.Context)
		}
		if ev.Details["grant_type"] == nil || ev.Details["error"] == nil || ev.Details["reason"] == nil {
			t.Errorf("token refusal details: %v", ev.Details)
		}
	}
	refusedCC := false
	for _, ev := range events.find(EventTokenRefused, "") {
		if ev.Details["client_id"] == "svc" && ev.Details["error"] == "invalid_client" {
			refusedCC = true
		}
	}
	if !refusedCC {
		t.Error("no token refusal event for the wrong client secret")
	}
	if in := events.find(EventSignIn, audit.OutcomeSuccess); len(in) > 0 && (in[0].Actor.ID.String() == "" || in[0].Details["method"] != "github") {
		t.Errorf("sign-in event: %+v", in[0])
	}
	if out := events.find(EventSignIn, audit.OutcomeFailure); len(out) > 0 && out[0].Details["reason"] != "invalid_state" {
		t.Errorf("refused sign-in reason: %v", out[0].Details)
	}
}

// TestLogsCarryNoSecretsJWTBearer runs the JWT-bearer grant of a service
// account and checks that neither the assertion, the key nor the token is
// logged.
func TestLogsCarryNoSecretsJWTBearer(t *testing.T) {
	logs := newLogCapture()
	events := &eventCapture{}
	f := newSAFixture(t)
	acct := f.account("ci")
	k := f.key(acct, serviceaccount.KeyInput{})
	s, err := NewEmbedded(Config{
		Issuer:   testIssuer,
		Features: FeatureConfig{EnableJWTAccessTokens: true},
		OAuth:    OAuthConfig{JWTBearer: JWTBearerConfig{Enabled: true}},
	},
		WithStorage(NewEntStorage(f.db, WithDefaultOwner(f.owner))),
		WithOrgsSource(NewEntOrgsSource(f.db, f.roles)),
		WithLogger(slog.New(logs)),
		WithAuditEmitter(events),
	)
	if err != nil {
		t.Fatal(err)
	}
	secrets := secretSet{}
	secrets.add("private key", strings.TrimSpace(strings.SplitN(k.PrivateKeyPEM, "\n", 3)[1]))
	signed := assertion{iss: acct.Identifier, sub: acct.Identifier, aud: s.TokenEndpointURL(), kid: k.KeyID}.
		sign(t, parsePrivateKey(t, k.PrivateKeyPEM), jose.ES256)
	secrets.add("assertion", signed)
	if status, body := postTokenWithProof(t, s, jwtBearerForm(signed), secrets); status != http.StatusOK {
		t.Fatalf("jwt-bearer: %d %v", status, body)
	}
	// The same assertion again is refused (its jti was used).
	if status, body := postTokenWithProof(t, s, jwtBearerForm(signed), secrets); status == http.StatusOK {
		t.Fatalf("replayed assertion accepted: %v", body)
	}
	assertNoSecrets(t, logs, events, secrets)
	if len(events.find(EventTokenRefused, audit.OutcomeFailure)) == 0 {
		t.Error("no token refusal event for the replayed assertion")
	}
}
