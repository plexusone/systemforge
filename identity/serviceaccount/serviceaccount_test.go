package serviceaccount_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/identity/serviceaccount"
)

// appVocab declares a small application role ladder.
type appVocab struct{ app string }

func (v appVocab) App() string { return v.app }
func (appVocab) Roles() authz.RolePermissions {
	return authz.RolePermissions{"viewer": {"item.read"}, "admin": {"item.read", "app.admin"}}
}
func (appVocab) Hierarchy() authz.RoleHierarchy {
	return authz.RoleHierarchy{"viewer": 10, "admin": 40}
}
func (v appVocab) Scopes() []string    { return nil }
func (appVocab) SpiceDBSchema() string { return "" }

type fixture struct {
	t         *testing.T
	db        *ent.Client
	svc       *serviceaccount.Service
	roles     *approle.Service
	orgs      organization.Service
	org       *organization.Organization
	owner     uuid.UUID
	announced []accesschange.Change
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	f := &fixture{t: t, db: db, orgs: organization.NewService(db)}
	sink := accesschange.SinkFunc(func(c accesschange.Change) { f.announced = append(f.announced, c) })
	reg := authz.NewVocabularyRegistry()
	if err := reg.Register(appVocab{app: "billing"}); err != nil {
		t.Fatal(err)
	}
	f.roles = approle.NewService(db, reg, approle.EntitleAll(reg), approle.WithAccessChangeSink(sink))
	svc, err := serviceaccount.New(serviceaccount.Config{
		Client:           db,
		Principals:       principal.NewService(db, principal.WithAccessChangeSink(sink)),
		Roles:            f.roles,
		AccessChangeSink: sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	owner, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier("owner@example.com").SetDisplayName("Owner").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.owner = owner.ID
	f.org = f.createOrg("acme", organization.OrgTypeTeam)
	return f
}

func (f *fixture) createOrg(slug string, typ organization.OrgType) *organization.Organization {
	f.t.Helper()
	org, err := f.orgs.Create(context.Background(), organization.CreateOrganizationInput{Name: slug, Slug: slug, OrgType: typ, OwnerPrincipalID: &f.owner})
	if err != nil {
		f.t.Fatalf("create organization: %v", err)
	}
	return org
}

func (f *fixture) create(name string, scopes ...string) *serviceaccount.Account {
	f.t.Helper()
	acct, err := f.svc.Create(context.Background(), serviceaccount.CreateInput{OrganizationID: f.org.ID, Name: name, Scopes: scopes, CreatedBy: f.owner})
	if err != nil {
		f.t.Fatalf("create account: %v", err)
	}
	return acct
}

// reasons returns the reasons of the access changes announced for id.
func (f *fixture) reasons(id uuid.UUID) []accesschange.Reason {
	var out []accesschange.Reason
	for _, c := range f.announced {
		if c.PrincipalID == id {
			out = append(out, c.Reason)
		}
	}
	return out
}

func TestCreate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.create("ci-publisher", "publish")
	if !strings.HasPrefix(acct.Identifier, "sa_") || len(acct.Identifier) != 29 {
		t.Errorf("identifier = %q, want sa_ and 26 characters", acct.Identifier)
	}
	if acct.OrganizationID != f.org.ID || !acct.Active || acct.Name != "ci-publisher" {
		t.Errorf("account = %+v", acct)
	}
	if acct.CreatedBy == nil || *acct.CreatedBy != f.owner {
		t.Errorf("created_by = %v, want %s", acct.CreatedBy, f.owner)
	}
	m, err := f.db.PrincipalMembership.Query().Where(principalmembership.PrincipalID(acct.ID)).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.Role != serviceaccount.MembershipRole || !m.Active || m.OrganizationID != f.org.ID {
		t.Errorf("membership = %+v", m)
	}
	p, err := f.db.Principal.Get(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != entprincipal.TypeService {
		t.Errorf("principal type = %s, want service", p.Type)
	}
	list, err := f.svc.List(ctx, f.org.ID)
	if err != nil || len(list) != 1 || list[0].ID != acct.ID {
		t.Fatalf("List = %+v, %v", list, err)
	}
}

func TestCreateRefusesUnsuitableOrganizations(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	personal := f.createOrg("owner", organization.OrgTypePersonal)
	inactive := f.createOrg("gone", organization.OrgTypeTeam)
	if err := f.db.Organization.UpdateOneID(inactive.ID).SetActive(false).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		org  uuid.UUID
		want error
	}{
		"personal": {personal.ID, serviceaccount.ErrPersonalOrganization},
		"inactive": {inactive.ID, serviceaccount.ErrOrganizationInactive},
		"unknown":  {uuid.New(), serviceaccount.ErrOrganizationNotFound},
	}
	for name, c := range cases {
		_, err := f.svc.Create(ctx, serviceaccount.CreateInput{OrganizationID: c.org, Name: "x"})
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	if _, err := f.svc.Create(ctx, serviceaccount.CreateInput{OrganizationID: f.org.ID}); !errors.Is(err, serviceaccount.ErrNameRequired) {
		t.Errorf("no name: err = %v", err)
	}
	if n, err := f.db.Principal.Query().Where(entprincipal.TypeEQ(entprincipal.TypeService)).Count(ctx); err != nil || n != 0 {
		t.Errorf("service principals after refusals = %d, %v", n, err)
	}
}

func TestGetRefusesOtherPrincipals(t *testing.T) {
	f := newFixture(t)
	if _, err := f.svc.Get(context.Background(), f.owner); !errors.Is(err, serviceaccount.ErrNotFound) {
		t.Errorf("Get(human) err = %v, want ErrNotFound", err)
	}
}

func pemOf(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestAddKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.create("ci", "publish")

	gen, err := f.svc.AddKey(ctx, acct.ID, serviceaccount.KeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	if gen.Algorithm != "ES256" || gen.KeyID == "" || !strings.Contains(gen.PrivateKeyPEM, "PRIVATE KEY") {
		t.Fatalf("generated key = %+v", gen)
	}
	if len(gen.Scopes) != 1 || gen.Scopes[0] != "publish" {
		t.Errorf("default key scopes = %v, want the account's", gen.Scopes)
	}
	block, _ := pem.Decode([]byte(gen.PrivateKeyPEM))
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := serviceaccount.ParsePublicKeyPEM(gen.PublicKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.(*ecdsa.PrivateKey).PublicKey.Equal(stored) {
		t.Error("the stored public key does not match the returned private key")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		pub any
		alg string
	}{"rsa": {&rsaKey.PublicKey, "RS256"}, "ed25519": {edPub, "EdDSA"}} {
		k, err := f.svc.AddKey(ctx, acct.ID, serviceaccount.KeyInput{PublicKeyPEM: pemOf(t, c.pub), Scopes: []string{"publish"}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if k.Algorithm != c.alg || k.PrivateKeyPEM != "" {
			t.Errorf("%s key = %+v", name, k)
		}
	}
	keys, err := f.svc.ListKeys(ctx, acct.ID)
	if err != nil || len(keys) != 3 {
		t.Fatalf("ListKeys = %d keys, %v", len(keys), err)
	}
}

func TestAddKeyRefusals(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.create("ci")
	short, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: a short key is what this test refuses
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	for name, in := range map[string]serviceaccount.KeyInput{
		"short rsa":     {PublicKeyPEM: pemOf(t, &short.PublicKey)},
		"p-384":         {PublicKeyPEM: pemOf(t, &p384.PublicKey)},
		"wrong alg":     {PublicKeyPEM: pemOf(t, &p256.PublicKey), Algorithm: "RS256"},
		"not pem":       {PublicKeyPEM: "not a key"},
		"expired":       {ExpiresAt: &past},
		"generated rsa": {Algorithm: "RS256"},
	} {
		if _, err := f.svc.AddKey(ctx, acct.ID, in); !errors.Is(err, serviceaccount.ErrInvalidKey) {
			t.Errorf("%s: err = %v, want ErrInvalidKey", name, err)
		}
	}
}

func TestRevokeKeyRecordsSessionsRevoked(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.create("ci")
	k1, err := f.svc.AddKey(ctx, acct.ID, serviceaccount.KeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	k2, err := f.svc.AddKey(ctx, acct.ID, serviceaccount.KeyInput{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.RevokeKey(ctx, acct.ID, k1.KeyID, "rotated"); err != nil {
		t.Fatal(err)
	}
	// Revoking a key while another remains still ends current tokens: they
	// may have been obtained with the revoked key.
	if got := f.reasons(acct.ID); len(got) != 1 || got[0] != accesschange.SessionsRevoked {
		t.Fatalf("revoking one of two keys announced %v, want sessions_revoked", got)
	}
	if err := f.svc.RevokeKey(ctx, acct.ID, k2.KeyID, "leaked"); err != nil {
		t.Fatal(err)
	}
	if got := f.reasons(acct.ID); len(got) != 2 || got[1] != accesschange.SessionsRevoked {
		t.Fatalf("revoking the last key announced %v, want sessions_revoked", got)
	}
	if err := f.svc.RevokeKey(ctx, acct.ID, k2.KeyID, "again"); err != nil {
		t.Fatalf("revoking a revoked key: %v", err)
	}
	if got := f.reasons(acct.ID); len(got) != 2 {
		t.Errorf("revoking again announced %v", got)
	}
	recorded, err := accesschange.Since(ctx, f.db, time.Time{}, 0)
	if err != nil || len(recorded) != 2 || recorded[1].Reason != accesschange.SessionsRevoked {
		t.Errorf("recorded = %+v, %v", recorded, err)
	}
	if err := f.svc.RevokeKey(ctx, acct.ID, "no-such-key", ""); !errors.Is(err, serviceaccount.ErrKeyNotFound) {
		t.Errorf("unknown key err = %v", err)
	}
	keys, err := f.svc.ListKeys(ctx, acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Usable(time.Now()) || !k.Revoked {
			t.Errorf("key %s still usable after revocation", k.KeyID)
		}
	}
}

func TestDisableEnable(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.create("ci")
	if err := f.svc.Disable(ctx, acct.ID, f.owner); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.Get(ctx, acct.ID)
	if err != nil || got.Active {
		t.Fatalf("after Disable: %+v, %v", got, err)
	}
	if r := f.reasons(acct.ID); len(r) != 1 || r[0] != accesschange.Deactivated {
		t.Errorf("Disable announced %v, want deactivated", r)
	}
	if err := f.svc.Enable(ctx, acct.ID, f.owner); err != nil {
		t.Fatal(err)
	}
	if got, err := f.svc.Get(ctx, acct.ID); err != nil || !got.Active {
		t.Fatalf("after Enable: %+v, %v", got, err)
	}
	if err := f.svc.Disable(ctx, f.owner, f.owner); !errors.Is(err, serviceaccount.ErrNotFound) {
		t.Errorf("Disable(human) err = %v, want ErrNotFound", err)
	}
}

func TestRoles(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.create("ci")
	if err := f.svc.GrantRole(ctx, acct.ID, "billing", "viewer", f.owner); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.GrantRole(ctx, acct.ID, "billing", "admin", f.owner); err != nil {
		t.Fatalf("granting a second role replaces the first: %v", err)
	}
	eff, err := f.roles.EffectiveRoles(ctx, acct.ID, f.org.ID)
	if err != nil || eff["billing"] != "admin" {
		t.Fatalf("effective roles = %v, %v", eff, err)
	}
	if err := f.svc.RemoveRole(ctx, acct.ID, "billing", f.owner); err != nil {
		t.Fatal(err)
	}
	eff, err = f.roles.EffectiveRoles(ctx, acct.ID, f.org.ID)
	if err != nil || len(eff) != 0 {
		t.Fatalf("effective roles after removal = %v, %v", eff, err)
	}
	reasons := f.reasons(acct.ID)
	if len(reasons) == 0 || reasons[len(reasons)-1] != accesschange.AppRoleChanged {
		t.Errorf("RemoveRole announced %v, want app_role_changed last", reasons)
	}
}

func TestDelete(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	acct := f.create("ci")
	if _, err := f.svc.AddKey(ctx, acct.ID, serviceaccount.KeyInput{}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.GrantRole(ctx, acct.ID, "billing", "viewer", f.owner); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(ctx, acct.ID, f.owner); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Get(ctx, acct.ID); !errors.Is(err, serviceaccount.ErrNotFound) {
		t.Errorf("Get after Delete err = %v", err)
	}
	if n, err := f.db.Credential.Query().Count(ctx); err != nil || n != 0 {
		t.Errorf("credentials left = %d, %v", n, err)
	}
	if n, err := f.db.PrincipalMembership.Query().Where(principalmembership.PrincipalID(acct.ID)).Count(ctx); err != nil || n != 0 {
		t.Errorf("memberships left = %d, %v", n, err)
	}
	r := f.reasons(acct.ID)
	if len(r) != 2 || r[0] != accesschange.Deactivated || r[1] != accesschange.AppRoleChanged {
		t.Errorf("Delete announced %v, want deactivated then app_role_changed", r)
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	if _, err := serviceaccount.New(serviceaccount.Config{}); err == nil {
		t.Error("New without a client succeeded")
	}
}
