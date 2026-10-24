package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/plexusone/systemforge/identity"
)

// TestConfidentialClientAuthenticates verifies that a confidential client
// authenticates at the token endpoint with its stored secret, by
// client_secret_basic and client_secret_post, including a secret still
// valid during a rotation, and that a wrong, revoked or expired secret
// does not.
func TestConfidentialClientAuthenticates(t *testing.T) {
	ctx := context.Background()
	f := newFlow(t)
	owner, err := f.db.Principal.Query().First(ctx)
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	const clientID = "backend"
	app, err := f.db.OAuthApp.Create().SetClientID(clientID).SetName("Backend").SetOwnerID(owner.ID).
		SetAllowedGrants([]string{"client_credentials"}).SetAllowedScopes([]string{"read"}).Save(ctx)
	if err != nil {
		t.Fatalf("app: %v", err)
	}
	addSecret := func(secret string, created time.Time, revoked bool, expires *time.Time) {
		t.Helper()
		h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		b := f.db.OAuthAppSecret.Create().SetAppID(app.ID).SetSecretHash(string(h)).SetSecretPrefix("backend").
			SetCreatedAt(created).SetRevoked(revoked)
		if expires != nil {
			b.SetExpiresAt(*expires)
		}
		if _, err := b.Save(ctx); err != nil {
			t.Fatalf("secret: %v", err)
		}
	}
	now := time.Now()
	past := now.Add(-time.Minute)
	addSecret("old-secret", now.Add(-2*time.Hour), false, nil)
	addSecret("new-secret", now.Add(-time.Hour), false, nil)
	addSecret("revoked-secret", now.Add(-3*time.Hour), true, nil)
	addSecret("expired-secret", now.Add(-4*time.Hour), false, &past)

	token := func(secret string, basic bool) error {
		form := url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}}
		if !basic {
			form.Set("client_id", clientID)
			form.Set("client_secret", secret)
		}
		r := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basic {
			r.SetBasicAuth(clientID, secret)
		}
		op := f.p.OAuth2Provider()
		ar, err := op.NewAccessRequest(ctx, r, f.p.Session(""))
		if err != nil {
			return err
		}
		for _, s := range ar.GetRequestedScopes() {
			ar.GrantScope(s)
		}
		_, err = op.NewAccessResponse(ctx, ar)
		return err
	}

	for _, basic := range []bool{true, false} {
		for _, secret := range []string{"new-secret", "old-secret"} {
			if err := token(secret, basic); err != nil {
				t.Errorf("basic=%v %s: %v", basic, secret, err)
			}
		}
		for _, secret := range []string{"wrong", "revoked-secret", "expired-secret", ""} {
			if err := token(secret, basic); err == nil {
				t.Errorf("basic=%v %q authenticated", basic, secret)
			}
		}
	}
}

// TestConfidentialClientArgon2idSecret verifies that a client secret stored
// as an Argon2id hash in PHC string format authenticates.
func TestConfidentialClientArgon2idSecret(t *testing.T) {
	ctx := context.Background()
	f := newFlow(t)
	owner, err := f.db.Principal.Query().First(ctx)
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	const clientID = "argon-backend"
	app, err := f.db.OAuthApp.Create().SetClientID(clientID).SetName("Backend").SetOwnerID(owner.ID).
		SetAllowedGrants([]string{"client_credentials"}).SetAllowedScopes([]string{"read"}).Save(ctx)
	if err != nil {
		t.Fatalf("app: %v", err)
	}
	h, err := identity.HashPassword("argon-secret", identity.DefaultArgon2idParams())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := f.db.OAuthAppSecret.Create().SetAppID(app.ID).SetSecretHash(h).SetSecretPrefix("argon").Save(ctx); err != nil {
		t.Fatalf("secret: %v", err)
	}
	for secret, want := range map[string]bool{"argon-secret": true, "wrong": false} {
		r := httptest.NewRequest(http.MethodPost, "/oauth/token",
			strings.NewReader(url.Values{"grant_type": {"client_credentials"}, "scope": {"read"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(clientID, secret)
		_, err := f.p.OAuth2Provider().NewAccessRequest(ctx, r, f.p.Session(""))
		if got := err == nil; got != want {
			t.Errorf("%s: authenticated=%v, want %v (err %v)", secret, got, want, err)
		}
	}
}
