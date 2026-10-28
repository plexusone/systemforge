package systemauth

import (
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"

	"github.com/plexusone/systemforge/identity/serviceaccount"
)

func TestJWTBearerConfigDefaultsAndValidation(t *testing.T) {
	cfg := Config{Issuer: testIssuer}
	cfg.ApplyDefaults()
	jb := cfg.OAuth.JWTBearer
	if jb.Enabled || jb.MaxAssertionLifetime.Duration() != 5*time.Minute || jb.TokenLifetime.Duration() != 15*time.Minute {
		t.Errorf("defaults = %+v", jb)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	long := cfg
	long.OAuth.JWTBearer.TokenLifetime = Duration(time.Hour)
	if err := long.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("an hour-long token lifetime: err = %v", err)
	}
	reserved := cfg
	reserved.Clients = []ClientConfig{{ID: JWTBearerClientID}}
	if err := reserved.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("a configured client with the reserved ID: err = %v", err)
	}
}

func TestJWTBearerDiscovery(t *testing.T) {
	f := newSAFixture(t)
	off := jwtBearerServer(t, f, func(c *Config) { c.OAuth.JWTBearer.Enabled = false })
	if slices.Contains(off.OpenIDConfiguration().GrantTypesSupported, GrantTypeJWTBearer) {
		t.Error("discovery lists the disabled grant")
	}
	on := jwtBearerServer(t, f, nil)
	if !slices.Contains(on.OpenIDConfiguration().GrantTypesSupported, GrantTypeJWTBearer) {
		t.Error("discovery omits the enabled grant")
	}
}

func TestJWTBearerNeedsKeyStorage(t *testing.T) {
	_, err := NewEmbedded(Config{Issuer: testIssuer, OAuth: OAuthConfig{JWTBearer: JWTBearerConfig{Enabled: true}}})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("memory storage without key storage: err = %v", err)
	}
}

func TestJWTBearerRequiresDPoP(t *testing.T) {
	f := newSAFixture(t)
	acct := f.account("ci")
	k := f.key(acct, serviceaccount.KeyInput{})
	s := jwtBearerServer(t, f, func(c *Config) {
		c.Clients = []ClientConfig{{ID: "legacy", Type: "public", Name: "Legacy", GrantTypes: []string{GrantTypeJWTBearer}, AllowBearerTokens: true}}
	})
	signed := assertion{iss: acct.Identifier, sub: acct.Identifier, aud: s.TokenEndpointURL(), kid: k.KeyID}.
		sign(t, parsePrivateKey(t, k.PrivateKeyPEM), jose.ES256)

	code, body := postToken(t, s, jwtBearerForm(signed), false)
	if code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("without a proof = %d %v, want invalid_dpop_proof", code, body)
	}
	form := jwtBearerForm(signed)
	form.Set("client_id", "legacy")
	code, body = postToken(t, s, form, false)
	if code != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
		t.Errorf("a bearer-exempt client without a proof = %d %v, want invalid_dpop_proof", code, body)
	}
}

func TestJWTBearerDisabledRefusesGrant(t *testing.T) {
	f := newSAFixture(t)
	acct := f.account("ci")
	k := f.key(acct, serviceaccount.KeyInput{})
	s := jwtBearerServer(t, f, func(c *Config) { c.OAuth.JWTBearer.Enabled = false })
	signed := assertion{iss: acct.Identifier, sub: acct.Identifier, aud: s.TokenEndpointURL(), kid: k.KeyID}.
		sign(t, parsePrivateKey(t, k.PrivateKeyPEM), jose.ES256)
	code, body := postToken(t, s, jwtBearerForm(signed), true)
	if code == http.StatusOK {
		t.Errorf("disabled grant issued a token: %v", body)
	}
}
