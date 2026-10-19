package console_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3" // registers the "sqlite3" driver
	"github.com/plexusone/connectforge/egress"
	"github.com/plexusone/connectforge/provider"
	"github.com/plexusone/connectforge/provider/apikey"
	"github.com/plexusone/connectforge/sqlstore"
	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/provider/local"
	"github.com/plexusone/omnivault/providers/memory"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/connections"
	"github.com/plexusone/systemforge/console"
	"github.com/plexusone/systemforge/keys"
)

const goodToken = "sf-console-good-token" //nolint:gosec // G101: a fake token for a local test server

// env is a console whose sessions are the "session" cookie holding a
// principal ID.
type env struct {
	h            http.Handler
	org          uuid.UUID
	admin        uuid.UUID
	member       uuid.UUID
	sessionError error
	signedOut    bool
}

func principalFromCookie(e *env) func(*http.Request) (uuid.UUID, error) {
	return func(r *http.Request) (uuid.UUID, error) {
		if e.sessionError != nil {
			return uuid.Nil, e.sessionError
		}
		c, err := r.Cookie("session")
		if err != nil {
			return uuid.Nil, console.ErrNoSession
		}
		id, err := uuid.Parse(c.Value)
		if err != nil {
			return uuid.Nil, console.ErrNoSession
		}
		return id, nil
	}
}

func newEnv(t *testing.T, webDir string, withConnections bool) *env {
	t.Helper()
	e := &env{org: uuid.New(), admin: uuid.New(), member: uuid.New()}
	o := console.Options{
		Principal: principalFromCookie(e),
		Organizations: func(_ context.Context, p uuid.UUID) ([]console.Organization, error) {
			role := "member"
			if p == e.admin {
				role = "admin"
			}
			return []console.Organization{{ID: e.org.String(), Slug: "acme", Name: "Acme", Type: "team", Role: role,
				Apps: map[string]string{"portfolio": "editor"}}}, nil
		},
		Apps: func(context.Context) ([]console.App, error) {
			return []console.App{{ID: "portfolio", Name: "Portfolio", URL: "https://portfolio.example.com", Order: 3}}, nil
		},
		ReturnTo: func(raw string) (string, error) {
			if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "https://app.example.com/") {
				return raw, nil
			}
			return "", errors.New("not allowed")
		},
		SignOut: func(http.ResponseWriter, *http.Request) error {
			e.signedOut = true
			return nil
		},
		WebDir: webDir,
	}
	if withConnections {
		o.Connections = openConnections(t, e)
	}
	c, err := console.New(o)
	if err != nil {
		t.Fatal(err)
	}
	e.h = c
	return e
}

func (e *env) do(t *testing.T, as uuid.UUID, method, target string, body any, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, "https://auth.example.com"+target, rd)
	if as != uuid.Nil {
		req.AddCookie(&http.Cookie{Name: "session", Value: as.String(), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w.Result(), w.Body.String()
}

// sameOrigin marks a request as a browser's same-origin fetch.
var sameOrigin = map[string]string{"Sec-Fetch-Site": "same-origin"}

func TestNewChecksOptions(t *testing.T) {
	if _, err := console.New(console.Options{}); err == nil {
		t.Fatal("a console without its functions was accepted")
	}
	e := &env{}
	o := console.Options{
		Principal:     principalFromCookie(e),
		Organizations: func(context.Context, uuid.UUID) ([]console.Organization, error) { return nil, nil },
		ReturnTo:      func(string) (string, error) { return "", nil },
		SignOut:       func(http.ResponseWriter, *http.Request) error { return nil },
		WebDir:        t.TempDir(), // no index.html
	}
	if _, err := console.New(o); err == nil {
		t.Fatal("a web directory without index.html was accepted")
	}
}

func TestSession(t *testing.T) {
	e := newEnv(t, "", false)
	// No session is a result, in the format @plexusone/host reads.
	resp, body := e.do(t, uuid.Nil, http.MethodGet, console.SessionPath, nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"authenticated":false`) {
		t.Fatalf("without a session: %d %s", resp.StatusCode, body)
	}
	resp, body = e.do(t, e.admin, http.MethodGet, console.SessionPath, nil, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("session: %d %v", resp.StatusCode, resp.Header)
	}
	var s struct {
		Authenticated bool
		Apps          []console.App
		User          struct {
			ID          string
			Memberships []struct {
				OrganizationID   string `json:"organization_id"`
				OrganizationName string `json:"organization_name"`
				Role             string
				Applications     map[string]string
			}
		}
	}
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		t.Fatal(err)
	}
	if !s.Authenticated || s.User.ID != e.admin.String() || len(s.User.Memberships) != 1 {
		t.Fatalf("session: %+v", s)
	}
	m := s.User.Memberships[0]
	if m.OrganizationID != e.org.String() || m.OrganizationName != "Acme" || m.Role != "admin" || m.Applications[console.AppID] != "admin" {
		t.Fatalf("membership: %+v", m)
	}
	// The products the person may open, and the catalog, for the console's
	// product switcher.
	if m.Applications["portfolio"] != "editor" || len(s.Apps) != 1 || s.Apps[0].URL != "https://portfolio.example.com" {
		t.Fatalf("products: %+v, catalog %+v", m.Applications, s.Apps)
	}

	e.sessionError = errors.New("store down")
	if resp, _ := e.do(t, e.admin, http.MethodGet, console.SessionPath, nil, nil); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("a failing session store: %d", resp.StatusCode)
	}
}

func TestSignInAndOut(t *testing.T) {
	e := newEnv(t, "", false)
	for target, want := range map[string]string{
		console.BFFPrefix + "/auth/login?return_to=%2Fconsole%2Forgs":  "/login?return_to=%2Fconsole%2Forgs",
		console.BFFPrefix + "/auth/github?return_to=%2Fconsole%2Forgs": "/login/github?return_to=%2Fconsole%2Forgs",
		console.BFFPrefix + "/auth/login":                              "/login",
	} {
		resp, _ := e.do(t, uuid.Nil, http.MethodGet, target, nil, nil)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != want {
			t.Errorf("%s: %d %s, want %s", target, resp.StatusCode, resp.Header.Get("Location"), want)
		}
	}
	for _, rt := range []string{"https://evil.example.com/", "//evil.example.com/"} {
		resp, _ := e.do(t, uuid.Nil, http.MethodGet, console.BFFPrefix+"/auth/login?return_to="+url.QueryEscape(rt), nil, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("return_to %s: %d", rt, resp.StatusCode)
		}
	}

	// Signing out must be same-origin.
	if resp, _ := e.do(t, e.admin, http.MethodPost, console.BFFPrefix+"/auth/logout", nil, map[string]string{"Sec-Fetch-Site": "cross-site"}); resp.StatusCode != http.StatusForbidden || e.signedOut {
		t.Fatalf("cross-site sign-out: %d, signed out %v", resp.StatusCode, e.signedOut)
	}
	if resp, _ := e.do(t, e.admin, http.MethodPost, console.BFFPrefix+"/auth/logout", nil, sameOrigin); resp.StatusCode != http.StatusNoContent || !e.signedOut {
		t.Fatalf("sign-out: %d, signed out %v", resp.StatusCode, e.signedOut)
	}
	if resp, _ := e.do(t, e.admin, http.MethodGet, console.BFFPrefix+"/nothing", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown session route: %d", resp.StatusCode)
	}
}

func TestReturnTo(t *testing.T) {
	e := newEnv(t, "", false)
	for raw, want := range map[string]int{
		"https://app.example.com/sites/new": http.StatusOK,
		"/console/orgs/x":                   http.StatusOK,
		"https://evil.example.com/":         http.StatusBadRequest,
		"":                                  http.StatusBadRequest,
	} {
		resp, body := e.do(t, e.admin, http.MethodGet, console.ReturnToPath+"?url="+url.QueryEscape(raw), nil, nil)
		if resp.StatusCode != want {
			t.Errorf("%q: %d %s, want %d", raw, resp.StatusCode, body, want)
		}
	}
	if resp, _ := e.do(t, uuid.Nil, http.MethodGet, console.ReturnToPath+"?url=/x", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("without a session: %d", resp.StatusCode)
	}
}

func TestUnknownAPIPath(t *testing.T) {
	e := newEnv(t, "", false)
	resp, body := e.do(t, e.admin, http.MethodGet, console.APIPrefix+"/v1/nothing", nil, nil)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "not found") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	// Without connections, their routes are not served.
	if resp, _ := e.do(t, e.admin, http.MethodGet, console.Prefix+connections.ProvidersPath, nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("providers without connections: %d", resp.StatusCode)
	}
}

func writePages(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "assets"), 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"index.html":       "<!doctype html><title>Console</title>",
		"assets/app-1.js":  "console.log(1)",
		"favicon.svg":      "<svg/>",
		"assets/.keep.txt": "",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(t.TempDir(), "secret.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPages(t *testing.T) {
	e := newEnv(t, writePages(t), false)

	// A console route without a session goes to sign-in and back.
	resp, _ := e.do(t, uuid.Nil, http.MethodGet, "/console/orgs/x/connections?provider=cloudflare", nil, nil)
	if resp.StatusCode != http.StatusFound ||
		resp.Header.Get("Location") != "/login?return_to=%2Fconsole%2Forgs%2Fx%2Fconnections%3Fprovider%3Dcloudflare" {
		t.Fatalf("without a session: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// With one, every route is the app, never cached, and not frameable.
	resp, body := e.do(t, e.admin, http.MethodGet, "/console/orgs/x/connections", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "<title>Console</title>") ||
		resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Frame-Options") != "DENY" ||
		!strings.Contains(resp.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("route: %d %v %s", resp.StatusCode, resp.Header, body)
	}

	// Assets need no session; hashed ones are immutable.
	resp, body = e.do(t, uuid.Nil, http.MethodGet, "/console/assets/app-1.js", nil, nil)
	if resp.StatusCode != http.StatusOK || body != "console.log(1)" || !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Fatalf("asset: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ = e.do(t, uuid.Nil, http.MethodGet, "/console/favicon.svg", nil, nil); resp.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("top-level file: %v", resp.Header)
	}

	for _, p := range []string{"/console/missing.js", "/console/../secret.txt", "/console/assets"} {
		if resp, _ := e.do(t, e.admin, http.MethodGet, p, nil, nil); resp.StatusCode == http.StatusOK && p != "/console/assets" {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := e.do(t, e.admin, http.MethodPost, "/console/orgs", nil, sameOrigin); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST to a page: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.admin, http.MethodGet, "/console", nil, nil); resp.StatusCode != http.StatusMovedPermanently {
		t.Errorf("/console: %d", resp.StatusCode)
	}
}

// openConnections opens connections on SQLite with a fake provider, where the
// admin may manage and the member only view.
func openConnections(t *testing.T, e *env) *connections.Connections {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+goodToken {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"result":{"id":"acct-9","name":"Acme","expires_on":"2027-01-17T00:00:00Z"}}`); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	p, err := apikey.New(apikey.Config{
		Manifest: provider.Manifest{
			Key: "fakecdn", DisplayName: "Fake CDN", BaseURLs: []string{srv.URL},
			AuthMethods: []provider.AuthMethod{{Key: "api_token", Fields: []provider.Field{{Name: "token", Secret: true, Required: true}}}},
		},
		Verify: apikey.Request{Path: "/verify", AccountIDPath: "result.id", AccountLabelPath: "result.name"},
	})
	if err != nil {
		t.Fatal(err)
	}
	reg := provider.NewRegistry()
	if err := reg.Register(p); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite3", "file:"+filepath.Join(t.TempDir(), "sf.db")+"?_fk=1&_txlock=immediate&_busy_timeout=10000")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	root := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, local.RootKeySize))
	k, err := keys.Open(context.Background(), keys.Options{
		Dir:      t.TempDir(),
		Root:     keys.VaultSource(memory.NewWithSecrets(map[string]string{"root": root}), "root"),
		Purposes: []keyforge.Purpose{connections.Purpose},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := k.Close(); err != nil {
			t.Error(err)
		}
	})
	c, err := connections.Open(connections.Options{
		DB: db, Dialect: sqlstore.SQLite, Keys: k, Providers: reg,
		Authorizer: roleAuthz{
			roles: map[uuid.UUID]string{e.admin: "admin", e.member: "member"},
			perms: connections.RolePermissions(authz.DefaultRolePermissions),
		},
		Egress: egress.Policy{AllowPrivate: true, AllowHTTP: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

type roleAuthz struct {
	roles map[uuid.UUID]string
	perms authz.RolePermissions
}

func (a roleAuthz) Can(_ context.Context, p authz.Principal, act authz.Action, r authz.Resource) (bool, error) {
	return a.perms.HasPermission(a.roles[p.ID], string(r.Type)+"."+string(act)), nil
}

func (a roleAuthz) CanAll(context.Context, authz.Principal, []authz.Action, authz.Resource) (bool, error) {
	return false, errors.New("not used")
}

func (a roleAuthz) CanAny(context.Context, authz.Principal, []authz.Action, authz.Resource) (bool, error) {
	return false, errors.New("not used")
}

func (a roleAuthz) Filter(context.Context, authz.Principal, authz.Action, []authz.Resource) ([]authz.Resource, error) {
	return nil, errors.New("not used")
}

func TestConnections(t *testing.T) {
	e := newEnv(t, "", true)
	base := console.Prefix + strings.Replace(connections.ConnectionsPath, "{org}", e.org.String(), 1)
	create := map[string]any{"provider": "fakecdn", "authMethod": "api_token", "displayName": "Prod", "fields": map[string]string{"token": goodToken}}

	// The providers are served.
	if resp, body := e.do(t, e.member, http.MethodGet, console.Prefix+connections.ProvidersPath, nil, nil); resp.StatusCode != http.StatusOK || !strings.Contains(body, "fakecdn") {
		t.Fatalf("providers: %d %s", resp.StatusCode, body)
	}

	// A cross-site request is refused before it reaches the API.
	resp, _ := e.do(t, e.admin, http.MethodPost, base, create, map[string]string{"Sec-Fetch-Site": "cross-site"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site create: %d", resp.StatusCode)
	}
	resp, _ = e.do(t, e.admin, http.MethodPost, base, create, map[string]string{"Origin": "https://evil.example.com"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("create from another origin: %d", resp.StatusCode)
	}

	// No session, then a member: refused by authentication, then by role.
	if resp, _ := e.do(t, uuid.Nil, http.MethodPost, base, create, sameOrigin); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("create without a session: %d", resp.StatusCode)
	}
	if resp, _ := e.do(t, e.member, http.MethodPost, base, create, sameOrigin); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("create as a member: %d", resp.StatusCode)
	}

	// The admin connects; the member sees it; the secret never comes back.
	resp, body := e.do(t, e.admin, http.MethodPost, base, create, sameOrigin)
	if resp.StatusCode != http.StatusCreated || strings.Contains(body, goodToken) || !strings.Contains(body, `"externalLabel":"Acme"`) {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	resp, body = e.do(t, e.member, http.MethodGet, base, nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"displayName":"Prod"`) || strings.Contains(body, goodToken) {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
}
