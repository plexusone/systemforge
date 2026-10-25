package signupapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/identity/signupgate"
)

type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) Emit(_ context.Context, ev *audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev.EventType)
	return nil
}

type fixture struct {
	t      *testing.T
	h      http.Handler
	client *ent.Client
	codes  *signupgate.CodeStore
	audit  *recorder
	admin  uuid.UUID
	member uuid.UUID
	other  uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing ent client: %v", err)
		}
	})
	people := principal.NewService(client)
	mk := func(email string) uuid.UUID {
		p, err := people.CreateHuman(t.Context(), principal.CreateHumanInput{Email: email, DisplayName: email})
		if err != nil {
			t.Fatal(err)
		}
		return p.ID
	}
	f := &fixture{t: t, client: client, audit: &recorder{},
		admin: mk("op@example.com"), member: mk("ada@example.com"), other: mk("grace@example.com")}
	f.codes = signupgate.NewCodeStore(client, signupgate.MemberOptions{})
	h, err := New(Options{
		Invites: signupgate.NewStore(client), Codes: f.codes, Waitlist: signupgate.NewWaitlist(client),
		Principal: func(r *http.Request) (uuid.UUID, error) {
			id, err := uuid.Parse(r.Header.Get("X-Test-Principal"))
			if err != nil {
				return uuid.Nil, errors.New("no session")
			}
			return id, nil
		},
		IsAdmin:   func(_ context.Context, id uuid.UUID) (bool, error) { return id == f.admin, nil },
		SignupURL: "https://auth.example.com/signup",
		Audit:     f.audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.h = h
	return f
}

// do sends a request as who (uuid.Nil for no session) and decodes the JSON
// response into out when it is not nil.
func (f *fixture) do(who uuid.UUID, method, path, body string, out any) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if who != uuid.Nil {
		req.Header.Set("X-Test-Principal", who.String())
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	if out != nil && rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			f.t.Fatalf("%s %s: decoding %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return rec
}

func TestAccess(t *testing.T) {
	f := newFixture(t)
	if rec := f.do(uuid.Nil, "GET", "/me/invites", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d", rec.Code)
	}
	if rec := f.do(f.member, "GET", "/admin/codes", "", nil); rec.Code != http.StatusForbidden {
		t.Errorf("member on an admin route: %d", rec.Code)
	}
	rec := f.do(f.admin, "GET", "/admin/codes", "", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("admin: %d, cache %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	req := httptest.NewRequest("POST", "/admin/codes", strings.NewReader(`{"max_uses":1}`))
	req.Header.Set("X-Test-Principal", f.admin.String())
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	cross := httptest.NewRecorder()
	f.h.ServeHTTP(cross, req)
	if cross.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: %d", cross.Code)
	}
	if rec := f.do(f.admin, "POST", "/admin/codes", `{"max_uses":1,"extra":true}`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", rec.Code)
	}
	if rec := f.do(f.admin, "GET", "/nope", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown route: %d", rec.Code)
	}
	var settings map[string]any
	f.do(f.member, "GET", "/settings", "", &settings)
	if settings["is_admin"] != false || settings["signup_url"] != "https://auth.example.com/signup" {
		t.Errorf("settings = %v", settings)
	}
}

func TestOperatorCodes(t *testing.T) {
	f := newFixture(t)
	var created createdCodeJSON
	rec := f.do(f.admin, "POST", "/admin/codes", `{"label":"launch","max_uses":20,"expires_in_days":30}`, &created)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if created.InviteCode == "" || created.Link != "https://auth.example.com/signup?code="+created.InviteCode ||
		created.Code.MaxUses != 20 || created.Code.ExpiresAt == nil || *created.Code.CreatedByPrincipalID != f.admin {
		t.Errorf("created = %+v", created)
	}
	for _, bad := range []string{`{"max_uses":0}`, `{"max_uses":1,"expires_in_days":-1}`, `{"max_uses":1,"label":"` + strings.Repeat("x", 101) + `"}`} {
		if rec := f.do(f.admin, "POST", "/admin/codes", bad, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", bad, rec.Code)
		}
	}
	list := f.do(f.admin, "GET", "/admin/codes?kind=operator&status=active", "", nil)
	if strings.Contains(list.Body.String(), created.InviteCode) || !strings.Contains(list.Body.String(), created.Code.ID.String()) {
		t.Errorf("list shows the code or misses it: %s", list.Body)
	}
	var revoked codeJSON
	if rec := f.do(f.admin, "POST", "/admin/codes/"+created.Code.ID.String()+"/revoke", "", &revoked); rec.Code != http.StatusOK || revoked.Status != signupgate.CodeRevoked {
		t.Errorf("revoke: %d %+v", rec.Code, revoked)
	}
	if rec := f.do(f.admin, "POST", "/admin/codes/"+uuid.NewString()+"/revoke", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoke unknown: %d", rec.Code)
	}
}

func TestMemberInvites(t *testing.T) {
	f := newFixture(t)
	if rec := f.do(f.member, "POST", "/me/codes", "", nil); rec.Code != http.StatusConflict {
		t.Fatalf("no allowance: %d", rec.Code)
	}
	if rec := f.do(f.admin, "PUT", "/admin/allowances", `{"email":"ADA@example.com","granted":2,"note":"early"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("set allowance: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(f.admin, "PUT", "/admin/allowances", `{"email":"nobody@example.com","granted":2}`, nil); rec.Code != http.StatusNotFound {
		t.Errorf("allowance for no account: %d", rec.Code)
	}
	var first createdCodeJSON
	if rec := f.do(f.member, "POST", "/me/codes", "", &first); rec.Code != http.StatusCreated || first.Code.Kind != "member" || first.Link == "" {
		t.Fatalf("create member code: %d %+v", rec.Code, first)
	}
	if rec := f.do(f.member, "POST", "/me/codes", "", nil); rec.Code != http.StatusCreated {
		t.Fatalf("second code: %d", rec.Code)
	}
	if rec := f.do(f.member, "POST", "/me/codes", "", nil); rec.Code != http.StatusConflict {
		t.Errorf("third code over an allowance of 2: %d", rec.Code)
	}
	if rec := f.do(f.other, "POST", "/me/codes/"+first.Code.ID.String()+"/revoke", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("another member revoking: %d", rec.Code)
	}
	if rec := f.do(f.member, "POST", "/me/codes/"+first.Code.ID.String()+"/revoke", "", nil); rec.Code != http.StatusOK {
		t.Errorf("revoking my code: %d", rec.Code)
	}
	var mine struct {
		Allowance int        `json:"allowance"`
		Held      int        `json:"held"`
		Remaining int        `json:"remaining"`
		Codes     []codeJSON `json:"codes"`
	}
	f.do(f.member, "GET", "/me/invites", "", &mine)
	if mine.Allowance != 2 || mine.Held != 1 || mine.Remaining != 1 || len(mine.Codes) != 2 {
		t.Errorf("my invites = %+v", mine)
	}
	var theirs struct {
		Codes []codeJSON `json:"codes"`
	}
	f.do(f.other, "GET", "/me/invites", "", &theirs)
	if len(theirs.Codes) != 0 {
		t.Errorf("another member sees %d codes", len(theirs.Codes))
	}
	var allowances struct {
		Allowances []allowanceJSON `json:"allowances"`
	}
	f.do(f.admin, "GET", "/admin/allowances", "", &allowances)
	if len(allowances.Allowances) != 1 || allowances.Allowances[0].Email != "ada@example.com" || allowances.Allowances[0].Held != 1 {
		t.Errorf("allowances = %+v", allowances)
	}
}

func TestInvitesWaitlistAndJoined(t *testing.T) {
	f := newFixture(t)
	var added struct {
		Invites []inviteJSON        `json:"invites"`
		Failed  []map[string]string `json:"failed"`
	}
	f.do(f.admin, "POST", "/admin/invites", `{"emails":["new@example.com","not an email"],"note":"launch"}`, &added)
	if len(added.Invites) != 1 || *added.Invites[0].InvitedByPrincipalID != f.admin || len(added.Failed) != 1 {
		t.Fatalf("added = %+v", added)
	}
	if rec := f.do(f.admin, "POST", "/admin/invites", `{"emails":[]}`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("no emails: %d", rec.Code)
	}
	if rec := f.do(f.admin, "DELETE", "/admin/invites/new@example.com", "", nil); rec.Code != http.StatusNoContent {
		t.Errorf("revoke invite: %d", rec.Code)
	}
	if rec := f.do(f.admin, "DELETE", "/admin/invites/new@example.com", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoke missing invite: %d", rec.Code)
	}

	w := signupgate.NewWaitlist(f.client)
	if err := w.Join(t.Context(), "wait@example.com", "v1", "Tell me"); err != nil {
		t.Fatal(err)
	}
	var invited struct {
		Invites []inviteJSON `json:"invites"`
		Error   string       `json:"error"`
	}
	f.do(f.admin, "POST", "/admin/waitlist/invite", `{"emails":["wait@example.com","nobody@example.com"]}`, &invited)
	if len(invited.Invites) != 1 || invited.Error == "" {
		t.Errorf("waitlist invite = %+v", invited)
	}
	var wl struct {
		Waitlist []waitlistJSON `json:"waitlist"`
	}
	f.do(f.admin, "GET", "/admin/waitlist", "", &wl)
	if len(wl.Waitlist) != 1 || wl.Waitlist[0].InvitedAt == nil {
		t.Errorf("waitlist = %+v", wl)
	}

	// One account through a member's code, one through an email invite.
	two := 1
	if err := f.codes.SetAllowance(t.Context(), f.member, &two, "", nil); err != nil {
		t.Fatal(err)
	}
	_, value, err := f.codes.CreateMemberCode(t.Context(), f.member)
	if err != nil {
		t.Fatal(err)
	}
	id, err := f.codes.Reserve(t.Context(), value)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.codes.Redeem(t.Context(), id, uuid.New(), "friend@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := signupgate.NewStore(f.client).Redeem(t.Context(), "wait@example.com", uuid.New()); err != nil {
		t.Fatal(err)
	}
	var joined struct {
		Joined []joinedJSON `json:"joined"`
	}
	f.do(f.admin, "GET", "/admin/joined", "", &joined)
	if len(joined.Joined) != 2 {
		t.Fatalf("joined = %+v", joined)
	}
	f.do(f.admin, "GET", "/admin/joined?inviter="+f.member.String(), "", &joined)
	if len(joined.Joined) != 1 || joined.Joined[0].Source != "code" || joined.Joined[0].Email != "friend@example.com" {
		t.Errorf("joined by member = %+v", joined)
	}
	f.do(f.admin, "GET", "/admin/joined?inviter="+f.admin.String(), "", &joined)
	if len(joined.Joined) != 1 || joined.Joined[0].Source != "invite" {
		t.Errorf("joined by admin = %+v", joined)
	}
	if rec := f.do(f.admin, "DELETE", "/admin/waitlist/wait@example.com", "", nil); rec.Code != http.StatusNoContent {
		t.Errorf("remove from waitlist: %d", rec.Code)
	}

	want := map[string]bool{
		signupgate.EventInviteCreated: true, signupgate.EventInviteRevoked: true,
		signupgate.EventWaitlistInvited: true,
	}
	for _, e := range f.audit.events {
		delete(want, e)
	}
	if len(want) != 0 {
		t.Errorf("missing audit events %v in %v", want, f.audit.events)
	}
}
