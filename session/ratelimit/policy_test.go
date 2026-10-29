package ratelimit

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/session/clientaddr"
)

// downStorage fails every call.
type downStorage struct{}

func (downStorage) Allow(context.Context, string, Limit) (Result, error) {
	return Result{}, errors.New("storage down")
}
func (downStorage) Reset(context.Context, string) error { return nil }
func (downStorage) Close() error                        { return nil }

// fullStorage reports ErrTooManyKeys.
type fullStorage struct{ downStorage }

func (fullStorage) Allow(context.Context, string, Limit) (Result, error) {
	return Result{}, ErrTooManyKeys
}

func newPolicy(t *testing.T, cfg PolicyConfig) *Policy {
	t.Helper()
	if cfg.Storage == nil {
		s := NewMemoryStorage()
		t.Cleanup(func() {
			if err := s.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		})
		cfg.Storage = s
	}
	p, err := NewPolicy(cfg)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return p
}

func serve(p *Policy, method, target, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	h := p.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPolicyDefaultLayer(t *testing.T) {
	p := newPolicy(t, PolicyConfig{Default: PerMinute(2), Routes: []Route{}})
	for i := range 2 {
		if w := serve(p, "GET", "/api/x", "192.0.2.1:1", nil); w.Code != http.StatusNoContent {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	w := serve(p, "GET", "/api/y", "192.0.2.1:1", nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: %d", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("Retry-After = %q, want at least 1", ra)
	}
	// Another address has its own bucket.
	if w := serve(p, "GET", "/api/x", "192.0.2.2:1", nil); w.Code != http.StatusNoContent {
		t.Errorf("other address: %d", w.Code)
	}
}

func TestPolicyHeaders(t *testing.T) {
	p := newPolicy(t, PolicyConfig{Default: PerMinute(10), Routes: []Route{}})
	w := serve(p, "GET", "/", "192.0.2.1:1", nil)
	if got := w.Header().Get("RateLimit-Policy"); got != `"default";q=10;w=60` {
		t.Errorf("RateLimit-Policy = %q", got)
	}
	if got := w.Header().Get("RateLimit"); !regexp.MustCompile(`^"default";r=9;t=(59|60)$`).MatchString(got) {
		t.Errorf("RateLimit = %q", got)
	}
	if w.Header().Get("X-RateLimit-Limit") != "10" || w.Header().Get("X-RateLimit-Remaining") != "9" || w.Header().Get("X-RateLimit-Reset") == "" {
		t.Errorf("X-RateLimit-* = %v", w.Header())
	}
}

func TestPolicyRouteLimits(t *testing.T) {
	p := newPolicy(t, PolicyConfig{Routes: MergeRoutes(DefaultRoutes(), Route{
		Name: RouteLogin, Paths: []string{"/login*"}, Limits: []RouteLimit{{Key: KeyAddress, Limit: PerMinute(1)}},
	})})
	if w := serve(p, "GET", "/login/github", "192.0.2.1:1", nil); w.Code != http.StatusNoContent {
		t.Fatalf("first login: %d", w.Code)
	}
	w := serve(p, "POST", "/login-token", "192.0.2.1:1", nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second login: %d", w.Code)
	}
	if got := strings.Join(w.Header().Values("RateLimit-Policy"), ","); !strings.Contains(got, `"default";q=300;w=60`) || !strings.Contains(got, `"login";q=1;w=60`) {
		t.Errorf("RateLimit-Policy = %q", got)
	}
	// Other routes are only under the default layer.
	if w := serve(p, "GET", "/oauth/userinfo", "192.0.2.1:1", nil); w.Code != http.StatusNoContent {
		t.Errorf("other route: %d", w.Code)
	}
}

func TestPolicyTokenClientKey(t *testing.T) {
	routes := MergeRoutes(DefaultRoutes(), Route{Name: RouteToken, Paths: []string{"/oauth/token"}, Limits: []RouteLimit{
		{Key: KeyClient, Limit: PerMinute(1)},
	}})
	p := newPolicy(t, PolicyConfig{Routes: routes, KnownClient: func(_ context.Context, id string) bool { return id == "app" }})
	h := p.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The handler still reads the body the middleware looked at.
		if err := r.ParseForm(); err != nil || r.PostForm.Get("client_id") == "" {
			t.Errorf("handler form: %v %v", r.PostForm, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	post := func(body, remote string) int {
		r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := post("grant_type=x&client_id=app", "192.0.2.1:1"); c != http.StatusNoContent {
		t.Fatalf("first: %d", c)
	}
	// The client's bucket is shared across addresses.
	if c := post("grant_type=x&client_id=app", "192.0.2.2:1"); c != http.StatusTooManyRequests {
		t.Fatalf("same client, other address: %d", c)
	}
	// Unknown clients share one bucket of their own.
	if c := post("grant_type=x&client_id=made-up-1", "192.0.2.3:1"); c != http.StatusNoContent {
		t.Fatalf("unknown client: %d", c)
	}
	if c := post("grant_type=x&client_id=made-up-2", "192.0.2.4:1"); c != http.StatusTooManyRequests {
		t.Fatalf("second unknown client: %d", c)
	}
}

func TestRequestClientID(t *testing.T) {
	r := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("client_id=ignored"))
	r.SetBasicAuth("my%20app", "secret")
	if got := RequestClientID(r); got != "my app" {
		t.Errorf("basic: %q", got)
	}
	big := "client_id=app&pad=" + strings.Repeat("a", maxPeekBody)
	r = httptest.NewRequest("POST", "/oauth/token", strings.NewReader(big))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := RequestClientID(r); got != "" {
		t.Errorf("oversized body: %q", got)
	}
	rest, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != big {
		t.Error("oversized body was not put back unchanged")
	}
	r = httptest.NewRequest("POST", "/oauth/token", strings.NewReader(`{"client_id":"app"}`))
	r.Header.Set("Content-Type", "application/json")
	if got := RequestClientID(r); got != "" {
		t.Errorf("json body: %q", got)
	}
}

func TestPolicyExemptions(t *testing.T) {
	p := newPolicy(t, PolicyConfig{Default: PerMinute(1), ExemptNetworks: []string{"10.0.0.0/8"}})
	for _, target := range []string{"/healthz", "/static/app.js", "/billing/webhook"} {
		for i := range 3 {
			if w := serve(p, "POST", target, "192.0.2.1:1", nil); w.Code != http.StatusNoContent {
				t.Fatalf("%s request %d: %d", target, i, w.Code)
			}
		}
	}
	for i := range 3 {
		if w := serve(p, "GET", "/oauth/introspect", "10.1.1.1:1", nil); w.Code != http.StatusNoContent {
			t.Fatalf("exempt network request %d: %d", i, w.Code)
		}
	}
}

func TestPolicyClientAddress(t *testing.T) {
	p := newPolicy(t, PolicyConfig{Default: PerMinute(1), Routes: []Route{}, Address: clientaddr.MustNew(clientaddr.LoopbackProxy())})
	xff := func(v string) map[string]string { return map[string]string{"X-Forwarded-For": v} }
	if w := serve(p, "GET", "/", "127.0.0.1:1", xff("203.0.113.1")); w.Code != http.StatusNoContent {
		t.Fatalf("first: %d", w.Code)
	}
	// A different client behind the same proxy has its own bucket.
	if w := serve(p, "GET", "/", "127.0.0.1:1", xff("203.0.113.2")); w.Code != http.StatusNoContent {
		t.Fatalf("other client: %d", w.Code)
	}
	// A spoofed left entry does not get a fresh bucket.
	if w := serve(p, "GET", "/", "127.0.0.1:1", xff("1.1.1.1, 203.0.113.1")); w.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed entry: %d", w.Code)
	}
}

func TestPolicyStorageOutage(t *testing.T) {
	p := newPolicy(t, PolicyConfig{Storage: downStorage{}})
	if w := serve(p, "GET", "/api", "192.0.2.1:1", nil); w.Code != http.StatusNoContent {
		t.Errorf("default layer during an outage: %d, want the request let through", w.Code)
	}
	for _, target := range []string{"/oauth/token", "/login", "/signup"} {
		if w := serve(p, "POST", target, "192.0.2.1:1", nil); w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s during an outage: %d, want 503", target, w.Code)
		}
	}
	closed := newPolicy(t, PolicyConfig{Storage: downStorage{}, DefaultFailClosed: true})
	if w := serve(closed, "GET", "/api", "192.0.2.1:1", nil); w.Code != http.StatusServiceUnavailable {
		t.Errorf("fail-closed default layer: %d", w.Code)
	}
	full := newPolicy(t, PolicyConfig{Storage: fullStorage{}})
	if w := serve(full, "GET", "/api", "192.0.2.1:1", nil); w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "60" {
		t.Errorf("full storage: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestRouteMatching(t *testing.T) {
	p := newPolicy(t, PolicyConfig{Routes: MergeRoutes(DefaultRoutes(),
		Route{Name: "login_token", Paths: []string{"/login-token"}, Methods: []string{"POST"}, Limits: []RouteLimit{{Key: KeyAddress, Limit: PerMinute(5)}}},
	)})
	cases := []struct{ method, path, want string }{
		{"GET", "/login", RouteLogin},
		{"GET", "/login/google/callback", RouteLogin},
		{"POST", "/login-token", "login_token"},
		{"GET", "/login-token", RouteLogin},
		{"GET", "/bff/auth", RouteBFFAuth},
		{"GET", "/bff/auth/login", RouteBFFAuth},
		{"GET", "/bff/authx", ""},
		{"POST", "/oauth/token", RouteToken},
		{"POST", "/x/../oauth/token", RouteToken},
		{"POST", "/oauth/token/x", ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		rt, ok := p.Route(r)
		if (c.want == "") == ok || (ok && rt.Name != c.want) {
			t.Errorf("%s %s: got %q, %v; want %q", c.method, c.path, rt.Name, ok, c.want)
		}
	}
}

func TestNewPolicyValidation(t *testing.T) {
	s := NewMemoryStorage()
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	for name, cfg := range map[string]PolicyConfig{
		"no storage":     {},
		"bad network":    {Storage: s, ExemptNetworks: []string{"nope"}},
		"no name":        {Storage: s, Routes: []Route{{Paths: []string{"/x"}}}},
		"bad path":       {Storage: s, Routes: []Route{{Name: "x", Paths: []string{"x*y"}}}},
		"exempt+limits":  {Storage: s, Routes: []Route{{Name: "x", Paths: []string{"/x"}, Exempt: true, Limits: []RouteLimit{{Key: KeyAddress, Limit: PerMinute(1)}}}}},
		"unknown key":    {Storage: s, Routes: []Route{{Name: "x", Paths: []string{"/x"}, Limits: []RouteLimit{{Key: "nope", Limit: PerMinute(1)}}}}},
		"duplicate name": {Storage: s, Routes: []Route{{Name: "x", Paths: []string{"/x"}}, {Name: "x", Paths: []string{"/y"}}}},
	} {
		if _, err := NewPolicy(cfg); err == nil {
			t.Errorf("%s: NewPolicy succeeded", name)
		}
	}
}

func TestSignedInLimiter(t *testing.T) {
	s := NewMemoryStorage()
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	l := NewSignedInLimiter(s, PerMinute(1))
	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	do := func(principal string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api", nil)
		if principal != "" {
			r = r.WithContext(requestprincipal.WithPrincipal(r.Context(), &requestprincipal.RequestPrincipal{PrincipalID: principal}))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for i := range 3 {
		if w := do(""); w.Code != http.StatusNoContent || w.Header().Get("RateLimit") != "" {
			t.Fatalf("anonymous request %d: %d %v", i, w.Code, w.Header())
		}
	}
	if w := do("p1"); w.Code != http.StatusNoContent || !strings.HasPrefix(w.Header().Get("RateLimit-Policy"), `"signed_in"`) {
		t.Fatalf("first signed-in: %d %v", w.Code, w.Header())
	}
	if w := do("p1"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second signed-in: %d", w.Code)
	}
	if w := do("p2"); w.Code != http.StatusNoContent {
		t.Fatalf("other principal: %d", w.Code)
	}
}

func TestCheckAndPeek(t *testing.T) {
	s := NewMemoryStorage()
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx := context.Background()
	limit := PerMinute(2)
	for range 3 {
		if _, exhausted, err := Exhausted(ctx, s, "fail", "k", limit); err != nil || exhausted {
			t.Fatalf("Exhausted before any failure: %v %v", exhausted, err)
		}
	}
	for range 2 {
		if _, err := Record(ctx, s, "fail", "k", limit); err != nil {
			t.Fatal(err)
		}
	}
	res, exhausted, err := Exhausted(ctx, s, "fail", "k", limit)
	if err != nil || !exhausted || res.RetryAfter <= 0 {
		t.Fatalf("Exhausted after two failures: %+v %v %v", res, exhausted, err)
	}

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	if d := Check(w, r, s, "acct", "a1", PerMinute(1), false, nil); d != Allowed {
		t.Fatalf("first Check: %v", d)
	}
	w = httptest.NewRecorder()
	if d := Check(w, r, s, "acct", "a1", PerMinute(1), false, nil); d != Refused || w.Code != http.StatusTooManyRequests {
		t.Fatalf("second Check: %v %d", d, w.Code)
	}
	w = httptest.NewRecorder()
	if d := Check(w, r, downStorage{}, "acct", "a1", PerMinute(1), false, nil); d != Unavailable || w.Code != http.StatusServiceUnavailable {
		t.Fatalf("Check on failing storage: %v %d", d, w.Code)
	}
	if d := Check(httptest.NewRecorder(), r, downStorage{}, "acct", "a1", PerMinute(1), true, nil); d != Allowed {
		t.Fatalf("fail-open Check: %v", d)
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for d, want := range map[time.Duration]int{0: 1, -time.Second: 1, 100 * time.Millisecond: 1, time.Second: 1, 1500 * time.Millisecond: 2, time.Minute: 60} {
		if got := RetryAfterSeconds(d); got != want {
			t.Errorf("RetryAfterSeconds(%v) = %d, want %d", d, got, want)
		}
	}
}

func TestLimiterRetryAfterNeverZero(t *testing.T) {
	s := NewMemoryStorage()
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	l := New(s, WithLimit(Limit{Rate: 1, Period: 10 * time.Millisecond}))
	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	var last *httptest.ResponseRecorder
	for range 2 {
		last = httptest.NewRecorder()
		h.ServeHTTP(last, httptest.NewRequest("GET", "/", nil))
	}
	if last.Code == http.StatusTooManyRequests && last.Header().Get("Retry-After") != "1" {
		t.Errorf("Retry-After = %q, want 1", last.Header().Get("Retry-After"))
	}
}
