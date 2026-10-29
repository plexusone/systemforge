package relyingparty_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/grokify/goauth/dpop"

	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// logCapture keeps every record as slog's text and JSON handlers write it
// and as the %+v of every attribute value, walked through groups.
type logCapture struct {
	st    *logCaptureStore
	text  slog.Handler
	json  slog.Handler
	attrs []slog.Attr
}

type logCaptureStore struct {
	mu     sync.Mutex
	text   bytes.Buffer
	json   bytes.Buffer
	values []string
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

func newLogCapture() *logCapture {
	st := &logCaptureStore{}
	opts := &slog.HandlerOptions{Level: slog.LevelDebug}
	return &logCapture{st: st,
		text: slog.NewTextHandler(lockedWriter{st, &st.text}, opts),
		json: slog.NewJSONHandler(lockedWriter{st, &st.json}, opts)}
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(ctx context.Context, r slog.Record) error {
	vals := []string{r.Message}
	for _, a := range c.attrs {
		vals = walkAttr(vals, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		vals = walkAttr(vals, a)
		return true
	})
	c.st.mu.Lock()
	c.st.values = append(c.st.values, vals...)
	c.st.mu.Unlock()
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
	return &logCapture{st: c.st, text: c.text.WithAttrs(attrs), json: c.json.WithAttrs(attrs), attrs: append(append([]slog.Attr{}, c.attrs...), attrs...)}
}

func (c *logCapture) WithGroup(name string) slog.Handler {
	return &logCapture{st: c.st, text: c.text.WithGroup(name), json: c.json.WithGroup(name), attrs: c.attrs}
}

func (c *logCapture) outputs() map[string]string {
	c.st.mu.Lock()
	defer c.st.mu.Unlock()
	return map[string]string{"text log": c.st.text.String(), "JSON log": c.st.json.String(), "log attributes": strings.Join(c.st.values, "\n")}
}

// TestBFFLogsCarryNoSecrets signs in and out through the BFF against a
// real SystemAuth, both logging at debug level, and checks that no code,
// token, state or session cookie reaches a log record.
func TestBFFLogsCarryNoSecrets(t *testing.T) {
	logs := newLogCapture()
	logger := slog.New(logs)
	var sa *systemauth.Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sa.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	const callback = "https://app.example.com/bff/auth/callback"
	var err error
	sa, err = systemauth.NewEmbedded(systemauth.Config{
		Issuer: srv.URL,
		Clients: []systemauth.ClientConfig{{
			ID: "app", Type: "public", Name: "App",
			RedirectURIs:  []string{callback},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
		Features: systemauth.FeatureConfig{RequirePKCE: true, EnableJWTAccessTokens: true},
	}, systemauth.WithSessionProvider(headerSession{}), systemauth.WithLogger(logger))
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	client, err := relyingparty.NewClient(ctx, relyingparty.Config{Issuer: srv.URL, ClientID: "app", RedirectURL: callback, DPoPKey: kp})
	if err != nil {
		t.Fatal(err)
	}
	bff, err := relyingparty.NewBFF(relyingparty.BFFConfig{Client: client, Principals: relyingparty.NewMemoryPrincipalStore(), Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{}
	add := func(what, v string) {
		if v != "" {
			secrets[v] = what
		}
	}

	w := httptest.NewRecorder()
	bff.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/bff/auth/login?return_to=%2Fhome", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("login: %d", w.Code)
	}
	authURL, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	add("login state", authURL.Query().Get("state"))
	stateCookie := w.Result().Cookies()[0]
	add("login state cookie", stateCookie.Value)

	human := &systemauth.HumanPrincipal{Email: "dev@example.com", EmailVerified: true, Active: true}
	if err := sa.Storage().CreateHuman(ctx, human); err != nil {
		t.Fatal(err)
	}
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	authReq.Header.Set("X-Test-User", human.ID.String())
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Do(authReq)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	add("authorization code", cb.Query().Get("code"))

	// A callback with a forged code is refused and logged.
	forged := cb.Query()
	forged.Set("code", "forged-"+cb.Query().Get("code"))
	add("forged authorization code", forged.Get("code"))
	bad := httptest.NewRequest(http.MethodGet, "/bff/auth/callback?"+forged.Encode(), nil)
	bad.AddCookie(stateCookie)
	bff.ServeHTTP(httptest.NewRecorder(), bad)

	// The real callback: start a fresh login to get a usable state.
	w = httptest.NewRecorder()
	bff.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/bff/auth/login?return_to=%2Fhome", nil))
	authURL, err = url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	add("login state", authURL.Query().Get("state"))
	stateCookie = w.Result().Cookies()[0]
	add("login state cookie", stateCookie.Value)
	authReq, err = http.NewRequestWithContext(ctx, http.MethodGet, authURL.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	authReq.Header.Set("X-Test-User", human.ID.String())
	resp, err = noRedirect.Do(authReq)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	cb, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	add("authorization code", cb.Query().Get("code"))
	req := httptest.NewRequest(http.MethodGet, "/bff/auth/callback?"+cb.RawQuery, nil)
	req.AddCookie(stateCookie)
	w = httptest.NewRecorder()
	bff.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	var sessCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == relyingparty.SessionCookieName {
			sessCookie = c
		}
	}
	if sessCookie == nil {
		t.Fatal("no session cookie")
	}
	add("session cookie", sessCookie.Value)
	sessReq := httptest.NewRequest(http.MethodGet, "/", nil)
	sessReq.AddCookie(sessCookie)
	sess, _, _, err := bff.CurrentSession(sessReq)
	if err != nil {
		t.Fatal(err)
	}
	add("access token", sess.AccessToken)
	add("refresh token", sess.RefreshToken)
	add("ID token", sess.IDToken)

	logout := httptest.NewRequest(http.MethodPost, "/bff/auth/logout", strings.NewReader("{}"))
	logout.Header.Set("Content-Type", "application/json")
	logout.AddCookie(sessCookie)
	w = httptest.NewRecorder()
	bff.ServeHTTP(w, logout)
	if w.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", w.Code)
	}

	for name, out := range logs.outputs() {
		if out == "" {
			t.Fatalf("%s is empty", name)
		}
		for secret, what := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("%s leaks the %s", name, what)
			}
		}
	}
}
