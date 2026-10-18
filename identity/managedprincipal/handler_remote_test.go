package managedprincipal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/session/ratelimit"
)

// remoteCaller calls a handler as a relying party would: the principal and
// the token's client come from the authenticated request.
type remoteCaller struct {
	t *testing.T
	h http.Handler
}

func (c remoteCaller) do(actor uuid.UUID, clientID, method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			c.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if actor != uuid.Nil {
		p := &requestprincipal.RequestPrincipal{PrincipalID: actor.String(), Claims: map[string]any{}}
		if clientID != "" {
			p.Claims["client_id"] = clientID
		}
		req = req.WithContext(requestprincipal.WithPrincipal(req.Context(), p))
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	return w
}

func expectStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status %d, want %d: %s", w.Code, want, w.Body)
	}
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", w.Body, err)
	}
}

func TestRemoteCreateUsesTheTokensClient(t *testing.T) {
	db := openSQLite(t)
	svc, _ := newService(t, db)
	c := remoteCaller{t, NewHandler(svc, WithRequestClient(RequestClientFromPrincipal))}
	teacher := addVerifiedHuman(t, db, "teacher@example.com")
	other := addVerifiedHuman(t, db, "other@example.com")
	self := []ManagerView{{PrincipalID: teacher, Role: RoleEducator}}

	// The token's client must allow managed principals; a body cannot
	// name another one.
	expectStatus(t, c.do(teacher, "other-app", http.MethodPost, "/", CreateRequest{DisplayName: "Robin", Managers: self}), http.StatusForbidden)
	expectStatus(t, c.do(teacher, "other-app", http.MethodPost, "/", CreateRequest{ClientID: client, DisplayName: "Robin", Managers: self}), http.StatusBadRequest)
	// No client on the request at all.
	expectStatus(t, c.do(teacher, "", http.MethodPost, "/", CreateRequest{DisplayName: "Robin", Managers: self}), http.StatusForbidden)
	// Only the caller may be the initial manager.
	expectStatus(t, c.do(teacher, client, http.MethodPost, "/", CreateRequest{DisplayName: "Robin",
		Managers: []ManagerView{{PrincipalID: teacher, Role: RoleEducator}, {PrincipalID: other, Role: RoleGuardian}}}), http.StatusBadRequest)
	expectStatus(t, c.do(teacher, client, http.MethodPost, "/", CreateRequest{DisplayName: "Robin",
		Managers: []ManagerView{{PrincipalID: other, Role: RoleGuardian}}}), http.StatusBadRequest)

	expectStatus(t, c.do(teacher, client, http.MethodPost, "/", CreateRequest{DisplayName: "Robin", Managers: self, Role: RoleEducator}), http.StatusBadRequest)
	// Role alone makes the caller the manager.
	expectStatus(t, c.do(teacher, client, http.MethodPost, "/", CreateRequest{DisplayName: "Sam", Role: RoleGuardian}), http.StatusCreated)

	w := c.do(teacher, client, http.MethodPost, "/", CreateRequest{DisplayName: "Robin", Managers: self})
	expectStatus(t, w, http.StatusCreated)
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	decodeBody(t, w, &created)

	// Adding a manager directly is refused; invitations remain.
	expectStatus(t, c.do(teacher, client, http.MethodPost, "/"+created.ID.String()+"/managers",
		ManagerView{PrincipalID: other, Role: RoleEducator}), http.StatusForbidden)
}

func TestRemoteIssueLoginToken(t *testing.T) {
	db := openSQLite(t)
	svc, rec := newService(t, db)
	c := remoteCaller{t, NewHandler(svc, WithRequestClient(RequestClientFromPrincipal))}
	teacher := addVerifiedHuman(t, db, "teacher@example.com")
	outsider := addVerifiedHuman(t, db, "outsider@example.com")
	learner, err := svc.Create(context.Background(), CreateInput{ClientID: client, DisplayName: "Robin",
		Managers: []ManagerInput{{PrincipalID: teacher, Role: RoleEducator}}, ActorID: teacher})
	if err != nil {
		t.Fatal(err)
	}
	path := "/" + learner.String() + "/login-tokens"

	expectStatus(t, c.do(uuid.Nil, client, http.MethodPost, path, IssueLoginTokenRequest{}), http.StatusUnauthorized)
	expectStatus(t, c.do(outsider, client, http.MethodPost, path, IssueLoginTokenRequest{}), http.StatusForbidden)
	expectStatus(t, c.do(teacher, "other-app", http.MethodPost, path, IssueLoginTokenRequest{}), http.StatusForbidden)
	expectStatus(t, c.do(teacher, client, http.MethodPost, path, IssueLoginTokenRequest{ClientID: schoolClient}), http.StatusBadRequest)
	past := time.Now().Add(-time.Hour)
	expectStatus(t, c.do(teacher, client, http.MethodPost, path, IssueLoginTokenRequest{ExpiresAt: &past}), http.StatusBadRequest)
	// An unknown principal answers like one the caller does not manage.
	expectStatus(t, c.do(teacher, client, http.MethodPost, "/"+uuid.NewString()+"/login-tokens", IssueLoginTokenRequest{}), http.StatusForbidden)

	w := c.do(teacher, client, http.MethodPost, path, IssueLoginTokenRequest{Name: "card", SingleUse: true})
	expectStatus(t, w, http.StatusCreated)
	var tok IssuedLoginToken
	decodeBody(t, w, &tok)
	if tok.Token == "" || tok.ID == uuid.Nil || !tok.SingleUse || tok.ExpiresAt == nil {
		t.Fatalf("issued %+v", tok)
	}
	if _, err := svc.creds.VerifyLoginToken(context.Background(), tok.Token, "203.0.113.7"); err != nil {
		t.Fatalf("issued token does not verify: %v", err)
	}
	var issued bool
	for _, typ := range rec.types() {
		issued = issued || typ == EventTokenIssued
	}
	if !issued {
		t.Fatalf("no audit event for the issued token: %v", rec.types())
	}

	// The listing shows the token without its value.
	// Other routes answer an unknown principal and a stranger's alike.
	for _, p := range []string{"/" + uuid.NewString() + "/login-tokens", path} {
		expectStatus(t, c.do(outsider, client, http.MethodGet, p, nil), http.StatusForbidden)
		expectStatus(t, c.do(outsider, client, http.MethodGet, p[:len(p)-len("/login-tokens")]+"/managers", nil), http.StatusForbidden)
	}

	w = c.do(teacher, client, http.MethodGet, path, nil)
	expectStatus(t, w, http.StatusOK)
	if bytes.Contains(w.Body.Bytes(), []byte(tok.Token)) {
		t.Fatal("listing exposes the token value")
	}
}

func TestListManagedBy(t *testing.T) {
	db := openSQLite(t)
	svc, _ := newService(t, db)
	c := remoteCaller{t, NewHandler(svc, WithRequestClient(RequestClientFromPrincipal))}
	ctx := context.Background()
	teacher := addVerifiedHuman(t, db, "teacher@example.com")
	parent := addVerifiedHuman(t, db, "parent@example.com")

	create := func(name string, managers ...ManagerInput) uuid.UUID {
		t.Helper()
		id, err := svc.Create(ctx, CreateInput{ClientID: client, DisplayName: name, Managers: managers, ActorID: managers[0].PrincipalID})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	both := create("Both", ManagerInput{PrincipalID: teacher, Role: RoleEducator}, ManagerInput{PrincipalID: teacher, Role: RoleGuardian})
	for i := range 3 {
		create("L"+string(rune('a'+i)), ManagerInput{PrincipalID: teacher, Role: RoleEducator})
	}
	create("Not mine", ManagerInput{PrincipalID: parent, Role: RoleGuardian})

	var all []ManagedSummary
	after := uuid.Nil
	for {
		page, err := svc.ListManagedBy(ctx, teacher, after, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		if len(page) > 2 {
			t.Fatalf("page of %d", len(page))
		}
		all = append(all, page...)
		after = page[len(page)-1].PrincipalID
	}
	if len(all) != 4 {
		t.Fatalf("listed %d principals: %+v", len(all), all)
	}
	for _, s := range all {
		if s.DisplayName == "Not mine" {
			t.Fatal("listed a principal the caller does not manage")
		}
		if s.PrincipalID == both && len(s.Roles) != 2 {
			t.Fatalf("roles of a principal managed twice: %v", s.Roles)
		}
	}

	// A removed relationship is no longer listed.
	if err := svc.AddManager(ctx, both, ManagerInput{PrincipalID: parent, Role: RoleGuardian}, teacher); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{RoleEducator, RoleGuardian} {
		if err := svc.RemoveManager(ctx, both, ManagerInput{PrincipalID: teacher, Role: role}, parent); err != nil {
			t.Fatal(err)
		}
	}
	w := c.do(teacher, client, http.MethodGet, "/?limit=50", nil)
	expectStatus(t, w, http.StatusOK)
	var listed struct {
		Managed []ManagedSummary `json:"managed_principals"`
	}
	decodeBody(t, w, &listed)
	if len(listed.Managed) != 3 {
		t.Fatalf("after removal: %+v", listed.Managed)
	}
	expectStatus(t, c.do(teacher, client, http.MethodGet, "/?after=nope", nil), http.StatusBadRequest)
	expectStatus(t, c.do(teacher, client, http.MethodGet, "/?limit=0", nil), http.StatusBadRequest)
	expectStatus(t, c.do(uuid.Nil, client, http.MethodGet, "/", nil), http.StatusUnauthorized)
}

type failingRates struct{ ratelimit.Storage }

func (failingRates) Allow(context.Context, string, ratelimit.Limit) (ratelimit.Result, error) {
	return ratelimit.Result{}, errors.New("storage down")
}

func TestCodeRateLimit(t *testing.T) {
	db := openSQLite(t)
	svc, _ := newService(t, db)
	rates := ratelimit.NewMemoryStorage()
	t.Cleanup(func() {
		if err := rates.Close(); err != nil {
			t.Error(err)
		}
	})
	c := remoteCaller{t, NewHandler(svc, WithRequestClient(RequestClientFromPrincipal),
		WithCodeRateLimit(rates, ratelimit.Limit{Rate: 2, Period: time.Minute}))}
	parent := addVerifiedHuman(t, db, "parent@example.com")
	other := addVerifiedHuman(t, db, "other@example.com")

	for range 2 {
		expectStatus(t, c.do(parent, client, http.MethodPost, "/claims/redeem", map[string]string{"code": "wrong"}), http.StatusBadRequest)
	}
	w := c.do(parent, client, http.MethodPost, "/claims/redeem", map[string]string{"code": "wrong"})
	expectStatus(t, w, http.StatusTooManyRequests)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	// The limit is shared by the code routes and is per caller.
	expectStatus(t, c.do(parent, client, http.MethodPost, "/manager-invites/accept", map[string]string{"token": "wrong"}), http.StatusTooManyRequests)
	expectStatus(t, c.do(other, client, http.MethodPost, "/claims/redeem", map[string]string{"code": "wrong"}), http.StatusBadRequest)

	broken := remoteCaller{t, NewHandler(svc, WithRequestClient(RequestClientFromPrincipal),
		WithCodeRateLimit(failingRates{}, DefaultCodeLimit))}
	expectStatus(t, broken.do(parent, client, http.MethodPost, "/claims/redeem", map[string]string{"code": "wrong"}), http.StatusServiceUnavailable)
}
