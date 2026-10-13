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

const goodToken = "sf-test-good-token" //nolint:gosec // G101: a fake token for a local test server

// fakeProvider is a plain-HTTP token API on loopback.
func fakeProvider(t *testing.T) (*httptest.Server, *apikey.Provider) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+goodToken {
			http.Error(w, "bad token "+r.Header.Get("Authorization"), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"result":{"id":"acct-9","name":"Acme"}}`); err != nil {
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

type apiEnv struct {
	h             http.Handler
	org           uuid.UUID
	admin, member uuid.UUID
}

func newAPI(t *testing.T) *apiEnv {
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
	c := open(t, connections.Options{
		Authorizer: az, Providers: reg,
		Egress: egress.Policy{AllowPrivate: true, AllowHTTP: true},
	})
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
