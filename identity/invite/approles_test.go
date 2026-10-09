package invite_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/invite"
	"github.com/plexusone/systemforge/internal/syncrec"
)

// ladderVocab declares the standard application role ladder.
type ladderVocab struct{ app string }

func (v ladderVocab) App() string { return v.app }
func (ladderVocab) Roles() authz.RolePermissions {
	return authz.RolePermissions{"viewer": {"item.read"}, "admin": {"item.read", "app.admin"}}
}
func (ladderVocab) Hierarchy() authz.RoleHierarchy {
	return authz.RoleHierarchy{"viewer": 10, "admin": 40}
}
func (v ladderVocab) Scopes() []string    { return []string{v.app + ":admin"} }
func (ladderVocab) SpiceDBSchema() string { return "" }

type roleFixture struct {
	t     *testing.T
	db    *ent.Client
	svc   invite.Service
	roles *approle.Service
	rec   *syncrec.Recorder
	org   uuid.UUID
	owner uuid.UUID
}

// newRoleFixture returns an organization entitled to applications alpha
// (one seat) and beta (unlimited).
func newRoleFixture(t *testing.T) *roleFixture {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	reg := authz.NewVocabularyRegistry()
	for _, app := range []string{"alpha", "beta", "gamma"} {
		if err := reg.Register(ladderVocab{app: app}); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	one := 1
	rec := syncrec.New()
	roles := approle.NewService(db, reg,
		approle.WithAuthzSyncer(rec, authz.SyncModeStrict),
		approle.WithEntitlementGrants(func(context.Context, uuid.UUID) (map[string]approle.Grant, error) {
			return map[string]approle.Grant{"alpha": {SeatLimit: &one}, "beta": {}}, nil
		}))
	orgID, owner := seedInviteOrg(t, db)
	return &roleFixture{t: t, db: db, roles: roles, rec: rec, org: orgID, owner: owner,
		svc: invite.NewService(db, "https://app.example.com", invite.WithAppRoles(roles), invite.WithAuthzSyncer(rec))}
}

func (f *roleFixture) person() uuid.UUID {
	f.t.Helper()
	p, err := f.db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("P").Save(context.Background())
	if err != nil {
		f.t.Fatalf("principal: %v", err)
	}
	return p.ID
}

func (f *roleFixture) create(role string, appRoles map[string]string) (*invite.InviteResult, error) {
	return f.svc.Create(context.Background(), invite.CreateInviteInput{
		OrganizationID: f.org, InviterPrincipalID: f.owner, Email: uuid.NewString() + "@example.com", Role: role, AppRoles: appRoles,
	})
}

func TestInviteAppRoleValidation(t *testing.T) {
	f := newRoleFixture(t)
	for name, tc := range map[string]struct {
		role  string
		roles map[string]string
		want  error
	}{
		"unknown application": {"member", map[string]string{"nope": "viewer"}, approle.ErrUnknownApplication},
		"unknown role":        {"member", map[string]string{"alpha": "boss"}, approle.ErrUnknownRole},
		"not entitled":        {"member", map[string]string{"gamma": "viewer"}, approle.ErrNotEntitled},
		"none chosen":         {"member", nil, invite.ErrAppRoleRequired},
		"none chosen, admin":  {"admin", map[string]string{}, invite.ErrAppRoleRequired},
	} {
		if _, err := f.create(tc.role, tc.roles); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	if _, err := f.create("collaborator", map[string]string{"beta": "viewer"}); err == nil {
		t.Error("collaborator invite with an application role was accepted")
	}
	// Owners hold every role implicitly, so none need be chosen.
	if _, err := f.create("owner", nil); err != nil {
		t.Errorf("owner invite without roles: %v", err)
	}
	res, err := f.create("member", map[string]string{"beta": "viewer", "alpha": "viewer"})
	if err != nil {
		t.Fatalf("valid invite: %v", err)
	}
	if got := res.Invite.AppRoles; len(got) != 2 || got["alpha"] != "viewer" || got["beta"] != "viewer" {
		t.Errorf("stored roles = %v", got)
	}
	// Roles need the approle service.
	plain := invite.NewService(f.db, "https://app.example.com")
	_, err = plain.Create(context.Background(), invite.CreateInviteInput{OrganizationID: f.org, InviterPrincipalID: f.owner, Email: "x@example.com", Role: "member", AppRoles: map[string]string{"beta": "viewer"}})
	if err == nil {
		t.Error("application roles accepted without an approle service")
	}
}

func TestAcceptGrantsAppRolesWithMembership(t *testing.T) {
	ctx := context.Background()
	f := newRoleFixture(t)
	res, err := f.create("member", map[string]string{"alpha": "viewer", "beta": "admin"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	p := f.person()
	if _, err := f.svc.Accept(ctx, invite.AcceptInviteInput{Token: tokenOf(t, res), PrincipalID: p}); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	got, err := f.roles.EffectiveRoles(ctx, p, f.org)
	if err != nil || len(got) != 2 || got["alpha"] != "viewer" || got["beta"] != "admin" {
		t.Errorf("effective roles = %v, %v", got, err)
	}
	want := "AddAppRole:" + p.String() + ":" + f.org.String() + ":beta:admin"
	found := false
	for _, c := range f.rec.Calls() {
		found = found || c == want
	}
	if !found {
		t.Errorf("syncer calls %v lack %s", f.rec.Calls(), want)
	}
}

func TestAcceptRefusedWhenARoleCannotBeGranted(t *testing.T) {
	ctx := context.Background()
	f := newRoleFixture(t)
	// First invitee takes alpha's only seat.
	first, err := f.create("member", map[string]string{"alpha": "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Accept(ctx, invite.AcceptInviteInput{Token: tokenOf(t, first), PrincipalID: f.person()}); err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	// The second invitation was valid when sent, but no seat remains.
	second, err := f.create("member", map[string]string{"beta": "viewer", "alpha": "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	p := f.person()
	_, err = f.svc.Accept(ctx, invite.AcceptInviteInput{Token: tokenOf(t, second), PrincipalID: p})
	if !errors.Is(err, approle.ErrNoSeats) {
		t.Fatalf("Accept without a seat = %v, want ErrNoSeats", err)
	}
	// Nothing was granted: no membership, no roles, invite still pending.
	n, cerr := f.db.PrincipalMembership.Query().Where(principalmembership.PrincipalID(p)).Count(ctx)
	if cerr != nil || n != 0 {
		t.Errorf("memberships after refused accept = %d, %v", n, cerr)
	}
	if held, _ := f.roles.ListForPrincipal(ctx, f.org, p); len(held) != 0 {
		t.Errorf("roles after refused accept = %v", held)
	}
	inv, err := f.svc.GetByID(ctx, second.Invite.ID)
	if err != nil || inv.Status != invite.StatusPending {
		t.Errorf("invite after refused accept = %+v, %v", inv, err)
	}
}

func TestInviteAPICarriesAppRoles(t *testing.T) {
	reg := authz.NewVocabularyRegistry()
	if err := reg.Register(ladderVocab{app: "alpha"}); err != nil {
		t.Fatal(err)
	}
	a := newInviteAPI(t, func(db *ent.Client) invite.ServiceOption {
		return invite.WithAppRoles(approle.NewService(db, reg, approle.EntitleAll(reg)))
	})
	create := func(roles map[string]string) (int, []byte) {
		return a.do(http.MethodPost, "/organizations/acme/invites", "admin", map[string]any{
			"email": "new@example.com", "role": "member", "app_roles": roles,
		})
	}

	// Nothing is preselected: no role chosen is refused, as is a bad one.
	if code, body := create(nil); code != http.StatusBadRequest || !strings.Contains(string(body), "application role") {
		t.Errorf("no role: %d %s", code, body)
	}
	if code, body := create(map[string]string{"alpha": "boss"}); code != http.StatusBadRequest {
		t.Errorf("bad role: %d %s", code, body)
	}
	code, body := create(map[string]string{"alpha": "viewer"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var created struct {
		Invite struct {
			AppRoles map[string]string `json:"app_roles"`
		} `json:"invite"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.Invite.AppRoles["alpha"] != "viewer" {
		t.Errorf("created = %s, %v", body, err)
	}
	code, body = a.do(http.MethodGet, "/organizations/acme/invites", "admin", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"app_roles":{"alpha":"viewer"}`) {
		t.Errorf("list: %d %s", code, body)
	}
}
