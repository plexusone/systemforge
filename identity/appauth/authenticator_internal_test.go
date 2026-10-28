package appauth

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/relyingparty"
)

func TestApplicationMemberships(t *testing.T) {
	src := relyingparty.MembershipSourceFunc(func(context.Context, relyingparty.MembershipQuery) ([]relyingparty.Membership, error) {
		return []relyingparty.Membership{
			{OrganizationID: "a", Applications: map[string]string{"app": "admin"}},
			{OrganizationID: "b", Applications: map[string]string{"other": "admin"}},
			{OrganizationID: "c", Applications: map[string]string{"app": "guest"}},
		}, nil
	})
	ids := func(ms []relyingparty.Membership) []string {
		out := []string{}
		for _, m := range ms {
			out = append(out, m.OrganizationID)
		}
		return out
	}
	ms, err := applicationMemberships(src, "app", nil).Memberships(context.Background(), relyingparty.MembershipQuery{})
	if err != nil || !reflect.DeepEqual(ids(ms), []string{"a", "c"}) {
		t.Errorf("any role: %v %v", ids(ms), err)
	}
	known := func(r string) bool { return r == "admin" }
	ms, err = applicationMemberships(src, "app", known).Memberships(context.Background(), relyingparty.MembershipQuery{})
	if err != nil || !reflect.DeepEqual(ids(ms), []string{"a"}) {
		t.Errorf("known roles: %v %v", ids(ms), err)
	}
	failing := relyingparty.MembershipSourceFunc(func(context.Context, relyingparty.MembershipQuery) ([]relyingparty.Membership, error) {
		return nil, errors.New("down")
	})
	if _, err := applicationMemberships(failing, "app", nil).Memberships(context.Background(), relyingparty.MembershipQuery{}); err == nil {
		t.Error("source error lost")
	}
}

func TestNewRefusals(t *testing.T) {
	ctx := context.Background()
	c := validConfig(t)
	md := &relyingparty.Metadata{
		Issuer: c.Issuer, AuthorizationEndpoint: c.Issuer + "/authorize",
		TokenEndpoint: c.Issuer + "/token", JWKSURI: c.Issuer + "/jwks",
	}
	store := relyingparty.NewMemoryPrincipalStore()
	sessions, states := relyingparty.NewMemorySessionStore(), relyingparty.NewMemoryLoginStateStore()

	if _, err := New(ctx, c, Options{Sessions: sessions, LoginStates: states, Metadata: md}); err == nil {
		t.Error("no principal store")
	}
	if _, err := New(ctx, c, Options{Principals: store, Metadata: md}); err == nil || !strings.Contains(err.Error(), "Sessions") {
		t.Errorf("no stores on a public URL: %v", err)
	}
	other := *md
	other.Issuer = "https://elsewhere.example.com"
	if _, err := New(ctx, c, Options{Principals: store, Sessions: sessions, LoginStates: states, Metadata: &other}); err == nil {
		t.Error("metadata for another issuer")
	}
	noKey := c
	noKey.DPoPKey = ""
	if _, err := New(ctx, noKey, Options{Principals: store, Sessions: sessions, LoginStates: states, Metadata: md}); err == nil {
		t.Error("no DPoP key")
	}
	if _, err := New(ctx, noKey, Options{Principals: store, Sessions: sessions, LoginStates: states, Metadata: md, EphemeralDPoPKey: true}); err != nil {
		t.Errorf("ephemeral key: %v", err)
	}
	local := c
	local.PublicURL = "http://localhost:8080"
	if _, err := New(ctx, local, Options{Principals: store, Metadata: md}); err != nil {
		t.Errorf("memory stores on loopback: %v", err)
	}
}

func TestClientUsesTheKey(t *testing.T) {
	c := validConfig(t)
	kp, err := ParseDPoPKey(c.DPoPKey)
	if err != nil {
		t.Fatal(err)
	}
	md := &relyingparty.Metadata{
		Issuer: c.Issuer, AuthorizationEndpoint: c.Issuer + "/authorize",
		TokenEndpoint: c.Issuer + "/token", JWKSURI: c.Issuer + "/jwks",
	}
	a, err := New(context.Background(), c, Options{
		Principals: relyingparty.NewMemoryPrincipalStore(), Metadata: md,
		Sessions: relyingparty.NewMemorySessionStore(), LoginStates: relyingparty.NewMemoryLoginStateStore(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Client().DPoPThumbprint(); got != kp.Thumbprint {
		t.Errorf("client thumbprint %s, key %s", got, kp.Thumbprint)
	}
}
