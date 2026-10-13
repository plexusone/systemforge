package connections_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/plexusone/connectionforge/egress"
	"github.com/plexusone/connectionforge/provider"
	"github.com/plexusone/connectionforge/provider/apikey"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/connections"
)

const (
	goodToken    = "sf-test-good-token"    //nolint:gosec // G101: a fake token for a local test server
	rotatedToken = "sf-test-rotated-token" //nolint:gosec // G101: as above
	otherToken   = "sf-test-other-token"   //nolint:gosec // G101: as above
)

// fakeProvider is a plain-HTTP token API on loopback.
func fakeProvider(t *testing.T) (*httptest.Server, *apikey.Provider) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("Content-Type", "application/json")
		body := `{"result":{"id":"acct-9","name":"Acme"}}`
		switch tok {
		case goodToken, rotatedToken:
		case otherToken:
			body = `{"result":{"id":"acct-10","name":"Someone Else"}}`
		default:
			http.Error(w, "bad token "+tok, http.StatusUnauthorized)
			return
		}
		if _, err := io.WriteString(w, body); err != nil {
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
	return srv, p
}

// roleAuthz answers from organization roles, as the rbac provider does with
// connections.RolePermissions.
type roleAuthz struct {
	roles map[uuid.UUID]string
	perms authz.RolePermissions
}

func (a roleAuthz) Can(_ context.Context, p authz.Principal, act authz.Action, r authz.Resource) (bool, error) {
	if r.OwnerID != nil && *r.OwnerID == p.ID {
		return true, nil
	}
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

var errNoToken = errors.New("no token")

// fakeGranter keeps resource roles in memory and validates them like the
// platform's grant service.
type fakeGranter struct {
	roles map[string]string // resource ID + "/" + principal
	by    map[string]uuid.UUID
}

func newFakeGranter() *fakeGranter {
	return &fakeGranter{roles: map[string]string{}, by: map[string]uuid.UUID{}}
}

func (g *fakeGranter) GrantResourceRole(_ context.Context, p uuid.UUID, r authz.ResourceRef, role string, by uuid.UUID) error {
	if !authz.ValidResourceRole(role) {
		return fmt.Errorf("%w: %q", authz.ErrInvalidResourceRole, role)
	}
	if r.Type != string(connections.ResourceType) {
		return fmt.Errorf("%w: %q", authz.ErrInvalidResource, r.Type)
	}
	k := r.ID + "/" + p.String()
	g.roles[k], g.by[k] = role, by
	return nil
}

func (g *fakeGranter) RevokeResourceRole(_ context.Context, p uuid.UUID, r authz.ResourceRef) error {
	k := r.ID + "/" + p.String()
	if _, ok := g.roles[k]; !ok {
		return authz.ErrGrantNotFound
	}
	delete(g.roles, k)
	return nil
}

func (g *fakeGranter) ListResourceGrants(_ context.Context, r authz.ResourceRef) ([]authz.Grant, error) {
	var out []authz.Grant
	for k, role := range g.roles {
		id, pid, _ := strings.Cut(k, "/")
		if id != r.ID {
			continue
		}
		p, err := uuid.Parse(pid)
		if err != nil {
			return nil, err
		}
		by := g.by[k]
		out = append(out, authz.Grant{PrincipalID: p, Resource: r, Role: role, GrantedBy: &by})
	}
	return out, nil
}

func (g *fakeGranter) ListResources(context.Context, uuid.UUID, string, authz.Action) (authz.ResourceSet, error) {
	return authz.ResourceSet{}, nil
}

type apiEnv struct {
	h             http.Handler
	org           uuid.UUID
	admin, member uuid.UUID
	granter       *fakeGranter
}

func newAPI(t *testing.T) *apiEnv { return newAPIWith(t, true) }

func newAPIWith(t *testing.T, withGrants bool) *apiEnv {
	t.Helper()
	_, p := fakeProvider(t)
	reg := provider.NewRegistry()
	if err := reg.Register(p); err != nil {
		t.Fatal(err)
	}
	e := &apiEnv{org: uuid.New(), admin: uuid.New(), member: uuid.New()}
	az := roleAuthz{
		roles: map[uuid.UUID]string{e.admin: "admin", e.member: "member"},
		perms: connections.RolePermissions(authz.DefaultRolePermissions),
	}
	opts := connections.Options{
		Authorizer: az, Providers: reg,
		Egress: egress.Policy{AllowPrivate: true, AllowHTTP: true},
	}
	if withGrants {
		e.granter = newFakeGranter()
		opts.Grants = e.granter
	}
	c := open(t, opts)
	// The bearer token is the principal ID; "read-only:" limits it to reads.
	auth := func(r *http.Request, scope string) (uuid.UUID, error) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		readOnly := strings.HasPrefix(tok, "read-only:")
		id, err := uuid.Parse(strings.TrimPrefix(tok, "read-only:"))
		if err != nil {
			return uuid.Nil, errNoToken
		}
		if readOnly && scope == connections.ScopeWrite {
			return uuid.Nil, fmt.Errorf("scope %s", scope)
		}
		return id, nil
	}
	writeAuthErr := func(w http.ResponseWriter, err error, _ string) {
		if errors.Is(err, errNoToken) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}
	e.h = c.Handler(auth, writeAuthErr, nil)
	return e
}

func (e *apiEnv) do(t *testing.T, as, method, path string, body any) (int, map[string]any, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, rd)
	if as != "" {
		r.Header.Set("Authorization", "Bearer "+as)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	raw := w.Body.String()
	var out map[string]any
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatalf("%s %s: not JSON: %q", method, path, raw)
		}
	}
	return w.Code, out, raw
}

func TestConnectionsAPI(t *testing.T) {
	e := newAPI(t)
	base := "/api/v1/organizations/" + e.org.String() + "/connections"
	admin, member := e.admin.String(), e.member.String()
	var bodies []string

	code, _, _ := e.do(t, "", http.MethodGet, base, nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", code)
	}
	code, out, raw := e.do(t, admin, http.MethodGet, connections.ProvidersPath, nil)
	if code != http.StatusOK || !strings.Contains(raw, `"key":"fakecdn"`) {
		t.Fatalf("providers: %d %v", code, out)
	}

	create := map[string]any{"provider": "fakecdn", "authMethod": "api_token", "displayName": "Prod", "fields": map[string]string{"token": goodToken}}
	if code, _, _ = e.do(t, member, http.MethodPost, base, create); code != http.StatusForbidden {
		t.Fatalf("member create: %d", code)
	}
	if code, _, _ = e.do(t, "read-only:"+admin, http.MethodPost, base, create); code != http.StatusForbidden {
		t.Fatalf("read-only token create: %d", code)
	}
	bad := map[string]any{"provider": "fakecdn", "authMethod": "api_token", "fields": map[string]string{"token": "sf-test-wrong-token"}}
	code, _, raw = e.do(t, admin, http.MethodPost, base, bad)
	bodies = append(bodies, raw)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("rejected token: %d %s", code, raw)
	}
	code, out, raw = e.do(t, admin, http.MethodPost, base, create)
	bodies = append(bodies, raw)
	if code != http.StatusCreated || out["state"] != "connected" || out["externalLabel"] != "Acme" || out["displayName"] != "Prod" {
		t.Fatalf("create: %d %s", code, raw)
	}
	id := out["id"].(string) //nolint:forcetypeassert // the API returns a string ID

	code, out, raw = e.do(t, member, http.MethodGet, base, nil)
	bodies = append(bodies, raw)
	if code != http.StatusOK || len(out["connections"].([]any)) != 1 { //nolint:forcetypeassert // a JSON array
		t.Fatalf("member list: %d %s", code, raw)
	}
	stranger := uuid.NewString()
	if code, _, _ = e.do(t, stranger, http.MethodGet, base+"/"+id, nil); code != http.StatusNotFound {
		t.Fatalf("stranger get: %d", code)
	}
	if code, _, _ = e.do(t, admin, http.MethodGet, "/api/v1/organizations/"+uuid.NewString()+"/connections/"+id, nil); code != http.StatusNotFound {
		t.Fatalf("get through another organization: %d", code)
	}
	if code, out, _ = e.do(t, admin, http.MethodPatch, base+"/"+id, map[string]string{"displayName": "Production"}); code != http.StatusOK || out["displayName"] != "Production" {
		t.Fatalf("rename: %d %v", code, out)
	}
	if code, _, _ = e.do(t, admin, http.MethodPatch, base+"/"+id, map[string]string{"bogus": "x"}); code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", code)
	}
	code, out, raw = e.do(t, admin, http.MethodPost, base+"/"+id+"/test", nil)
	bodies = append(bodies, raw)
	if code != http.StatusOK || out["health"].(map[string]any)["lastValidation"] != "ok" { //nolint:forcetypeassert // a JSON object
		t.Fatalf("test: %d %s", code, raw)
	}
	if code, _, _ = e.do(t, member, http.MethodDelete, base+"/"+id, nil); code != http.StatusForbidden {
		t.Fatalf("member disconnect: %d", code)
	}
	if code, out, _ = e.do(t, admin, http.MethodDelete, base+"/"+id, nil); code != http.StatusOK || out["state"] != "disconnected" {
		t.Fatalf("disconnect: %d %v", code, out)
	}
	if code, _, _ = e.do(t, admin, http.MethodPost, base+"/"+id+"/test", nil); code != http.StatusConflict {
		t.Fatalf("test after disconnect: %d", code)
	}

	for _, b := range bodies {
		if strings.Contains(b, goodToken) || strings.Contains(b, "sf-test-wrong-token") {
			t.Fatalf("a response contains a token: %s", b)
		}
	}
}

func (e *apiEnv) path(id, tail string) string {
	p := "/api/v1/organizations/" + e.org.String() + "/connections"
	if id != "" {
		p += "/" + id
	}
	return p + tail
}

// connect creates a connection as admin and returns its ID.
func (e *apiEnv) connect(t *testing.T) string {
	t.Helper()
	code, out, raw := e.do(t, e.admin.String(), http.MethodPost, e.path("", ""), map[string]any{
		"provider": "fakecdn", "authMethod": "api_token", "displayName": "Prod",
		"fields": map[string]string{"token": goodToken},
	})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, raw)
	}
	id, ok := out["id"].(string)
	if !ok {
		t.Fatalf("no id: %s", raw)
	}
	return id
}

func TestConnectionsAPIReconnect(t *testing.T) {
	e := newAPI(t)
	id := e.connect(t)
	admin, member := e.admin.String(), e.member.String()
	body := func(tok string) map[string]any { return map[string]any{"fields": map[string]string{"token": tok}} }

	code, out, raw := e.do(t, admin, http.MethodPost, e.path(id, "/reconnect"), body(rotatedToken))
	if code != http.StatusOK || out["state"] != "connected" || out["id"] != id {
		t.Fatalf("reconnect: %d %s", code, raw)
	}
	if strings.Contains(raw, rotatedToken) {
		t.Fatalf("the response contains the token: %s", raw)
	}
	code, _, raw = e.do(t, admin, http.MethodPost, e.path(id, "/reconnect"), body("sf-test-wrong-token"))
	if code != http.StatusUnprocessableEntity || strings.Contains(raw, "sf-test-wrong-token") {
		t.Fatalf("rejected token: %d %s", code, raw)
	}
	code, _, raw = e.do(t, admin, http.MethodPost, e.path(id, "/reconnect"), body(otherToken))
	if code != http.StatusUnprocessableEntity || !strings.Contains(raw, "different account") {
		t.Fatalf("another account: %d %s", code, raw)
	}
	if code, _, _ = e.do(t, member, http.MethodPost, e.path(id, "/reconnect"), body(rotatedToken)); code != http.StatusForbidden {
		t.Fatalf("member reconnect: %d", code)
	}
	if code, _, _ = e.do(t, admin, http.MethodPost, e.path(id, "/reconnect"), map[string]any{"bogus": 1}); code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", code)
	}
}

func TestConnectionsAPIBindings(t *testing.T) {
	e := newAPI(t)
	id := e.connect(t)
	admin, member := e.admin.String(), e.member.String()
	bind := map[string]string{"consumerKind": "portfolio.site", "consumerId": "impactchiefs.com", "purpose": "traffic"}

	if code, _, _ := e.do(t, member, http.MethodPut, e.path(id, "/bindings"), bind); code != http.StatusForbidden {
		t.Fatalf("a viewer bound a connection: %d", code)
	}
	for range 2 { // idempotent
		if code, _, raw := e.do(t, admin, http.MethodPut, e.path(id, "/bindings"), bind); code != http.StatusNoContent {
			t.Fatalf("bind: %d %s", code, raw)
		}
	}
	code, out, raw := e.do(t, member, http.MethodGet, e.path(id, "/bindings"), nil)
	list, _ := out["bindings"].([]any)
	if code != http.StatusOK || len(list) != 1 || !strings.Contains(raw, `"consumerId":"impactchiefs.com"`) {
		t.Fatalf("list: %d %s", code, raw)
	}
	if code, _, _ := e.do(t, admin, http.MethodPut, e.path(id, "/bindings"), map[string]string{"consumerKind": "x"}); code != http.StatusBadRequest {
		t.Fatalf("incomplete binding: %d", code)
	}
	del := e.path(id, "/bindings") + "?kind=portfolio.site&id=impactchiefs.com&purpose=traffic"
	if code, _, _ := e.do(t, admin, http.MethodDelete, del, nil); code != http.StatusNoContent {
		t.Fatalf("unbind: %d", code)
	}
	if _, out, _ = e.do(t, admin, http.MethodGet, e.path(id, "/bindings"), nil); len(out["bindings"].([]any)) != 0 { //nolint:forcetypeassert // a JSON array
		t.Fatalf("binding survived: %v", out)
	}
}

func TestConnectionsAPIGrants(t *testing.T) {
	e := newAPI(t)
	id := e.connect(t)
	admin, member := e.admin.String(), e.member.String()
	friend := uuid.New().String()
	grant := e.path(id, "/grants/"+friend)

	// The member sees the connection but may not share it.
	if code, _, _ := e.do(t, member, http.MethodPut, grant, map[string]string{"role": "contributor"}); code != http.StatusForbidden {
		t.Fatalf("member shared: %d", code)
	}
	if code, _, raw := e.do(t, admin, http.MethodPut, grant, map[string]string{"role": "contributor"}); code != http.StatusNoContent {
		t.Fatalf("grant: %d %s", code, raw)
	}
	code, out, raw := e.do(t, admin, http.MethodGet, e.path(id, "/grants"), nil)
	gs, _ := out["grants"].([]any)
	if code != http.StatusOK || len(gs) != 1 || !strings.Contains(raw, friend) ||
		!strings.Contains(raw, `"role":"contributor"`) || !strings.Contains(raw, `"grantedBy":"`+admin+`"`) {
		t.Fatalf("list grants: %d %s", code, raw)
	}
	if code, _, _ := e.do(t, admin, http.MethodPut, grant, map[string]string{"role": "owner"}); code != http.StatusBadRequest {
		t.Fatalf("invalid role: %d", code)
	}
	if code, _, _ := e.do(t, admin, http.MethodPut, e.path(id, "/grants/not-an-id"), map[string]string{"role": "viewer"}); code != http.StatusBadRequest {
		t.Fatalf("invalid principal: %d", code)
	}
	if code, _, _ := e.do(t, admin, http.MethodDelete, grant, nil); code != http.StatusNoContent {
		t.Fatalf("revoke: %d", code)
	}
	if code, _, _ := e.do(t, admin, http.MethodDelete, grant, nil); code != http.StatusNotFound {
		t.Fatalf("revoke again: %d", code)
	}
	// A connection that is not the caller's organization's is not found.
	other := "/api/v1/organizations/" + uuid.NewString() + "/connections/" + id + "/grants"
	if code, _, _ := e.do(t, admin, http.MethodGet, other, nil); code != http.StatusNotFound {
		t.Fatalf("another organization: %d", code)
	}
}

func TestGrantRoutesNeedAGranter(t *testing.T) {
	e := newAPIWith(t, false)
	id := e.connect(t)
	if code, _, _ := e.do(t, e.admin.String(), http.MethodGet, e.path(id, "/grants"), nil); code != http.StatusNotImplemented {
		t.Fatalf("without a granter: %d", code)
	}
}

func TestVocabularyAcceptsConnectionGrants(t *testing.T) {
	v := connections.Vocabulary()
	if err := authz.ValidateVocabulary(v); err != nil {
		t.Fatalf("vocabulary: %v", err)
	}
	reg := authz.NewVocabularyRegistry()
	for range 2 { // idempotent
		if err := connections.RegisterVocabulary(reg); err != nil {
			t.Fatal(err)
		}
	}
	if err := reg.ValidateResourceType(string(connections.ResourceType)); err != nil {
		t.Fatalf("resource type: %v", err)
	}
	if got := strings.Join(reg.AllScopes(), ","); got != connections.ScopeRead+","+connections.ScopeWrite {
		t.Fatalf("scopes: %s", got)
	}
	if err := connections.RegisterVocabulary(nil); err != nil {
		t.Fatalf("nil registry: %v", err)
	}
}
