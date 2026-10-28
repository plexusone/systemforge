package systemauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"

	entcredential "github.com/plexusone/systemforge/identity/ent/credential"
	"github.com/plexusone/systemforge/identity/ent/serviceprincipal"
	"github.com/plexusone/systemforge/identity/serviceaccount"
)

// jwtPayload decodes the claims of a JWT without verifying it.
func jwtPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestJWTBearerIssuesServiceAccountToken(t *testing.T) {
	f := newSAFixture(t)
	ctx := context.Background()
	acct := f.account("ci")
	k := f.key(acct, serviceaccount.KeyInput{})
	if err := f.svc.GrantRole(ctx, acct.ID, "billing", "viewer", f.owner); err != nil {
		t.Fatal(err)
	}
	s := jwtBearerServer(t, f, func(c *Config) { c.OAuth.JWTBearer.TokenLifetime = Duration(7 * time.Minute) })
	signed := assertion{iss: acct.Identifier, sub: acct.Identifier, aud: s.TokenEndpointURL(), kid: k.KeyID}.
		sign(t, parsePrivateKey(t, k.PrivateKeyPEM), jose.ES256)

	code, body := postToken(t, s, jwtBearerForm(signed), true)
	if code != http.StatusOK {
		t.Fatalf("token request = %d %v", code, body)
	}
	if body["token_type"] != TokenTypeDPoP {
		t.Errorf("token_type = %v, want DPoP", body["token_type"])
	}
	if _, ok := body["refresh_token"]; ok {
		t.Error("the grant issued a refresh token")
	}
	if exp, _ := body["expires_in"].(float64); exp < 400 || exp > 420 {
		t.Errorf("expires_in = %v, want the grant's token lifetime (420s)", body["expires_in"])
	}

	access, _ := body["access_token"].(string)
	claims := jwtPayload(t, access)
	if claims["sub"] != acct.ID.String() {
		t.Errorf("sub = %v, want the principal ID %s", claims["sub"], acct.ID)
	}
	if claims[PrincipalTypeClaim] != PrincipalTypeService {
		t.Errorf("principal_type = %v, want service", claims[PrincipalTypeClaim])
	}
	if claims["client_id"] != JWTBearerClientID {
		t.Errorf("client_id = %v", claims["client_id"])
	}
	if aud, ok := claims["aud"].([]any); ok && len(aud) > 0 {
		t.Errorf("aud = %v, want none from the assertion", aud)
	}
	orgs, _ := claims[OrgsClaim].([]any)
	if len(orgs) != 1 {
		t.Fatalf("orgs = %v, want the account's organization", claims[OrgsClaim])
	}
	org, _ := orgs[0].(map[string]any)
	apps, _ := org["apps"].(map[string]any)
	if org["id"] != f.org.ID.String() || org["role"] != serviceaccount.MembershipRole || apps["billing"] != "viewer" {
		t.Errorf("orgs[0] = %v", org)
	}

	cred, err := f.db.Credential.Query().Where(entcredential.KeyIDEQ(k.KeyID)).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cred.LastUsedAt == nil || cred.LastUsedIP != "203.0.113.7" {
		t.Errorf("key last use = %v from %q", cred.LastUsedAt, cred.LastUsedIP)
	}
	sp, err := f.db.ServicePrincipal.Query().Where(serviceprincipal.PrincipalID(acct.ID)).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sp.LastUsedAt == nil {
		t.Error("the service principal's last use was not recorded")
	}
}

func TestJWTBearerWithoutKeyID(t *testing.T) {
	f := newSAFixture(t)
	acct := f.account("ci")
	f.key(acct, serviceaccount.KeyInput{})
	k := f.key(acct, serviceaccount.KeyInput{})
	s := jwtBearerServer(t, f, nil)
	signed := assertion{iss: acct.Identifier, sub: acct.Identifier, aud: testIssuer}.
		sign(t, parsePrivateKey(t, k.PrivateKeyPEM), jose.ES256)
	code, body := postToken(t, s, jwtBearerForm(signed), true)
	if code != http.StatusOK {
		t.Fatalf("an assertion without kid, audience the issuer = %d %v", code, body)
	}
	cred, err := f.db.Credential.Query().Where(entcredential.KeyIDEQ(k.KeyID)).Only(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred.LastUsedAt == nil {
		t.Error("the use of the key that verified the assertion was not recorded")
	}
}

func TestJWTBearerScopes(t *testing.T) {
	f := newSAFixture(t)
	acct := f.account("ci", "publish", "read")
	k := f.key(acct, serviceaccount.KeyInput{Scopes: []string{"publish"}})
	s := jwtBearerServer(t, f, nil)
	key := parsePrivateKey(t, k.PrivateKeyPEM)
	a := assertion{iss: acct.Identifier, sub: acct.Identifier, aud: s.TokenEndpointURL(), kid: k.KeyID}

	code, body := postToken(t, s, jwtBearerForm(a.sign(t, key, jose.ES256), "publish"), true)
	if code != http.StatusOK || body["scope"] != "publish" {
		t.Errorf("a scope the key and account allow = %d %v", code, body)
	}
	code, body = postToken(t, s, jwtBearerForm(a.sign(t, key, jose.ES256), "read"), true)
	if code != http.StatusBadRequest || body["error"] != "invalid_scope" {
		t.Errorf("a scope the key lacks = %d %v, want invalid_scope", code, body)
	}
}

func TestJWTBearerRefusesAnotherAlgorithm(t *testing.T) {
	f := newSAFixture(t)
	acct := f.account("ci")
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	k := f.key(acct, serviceaccount.KeyInput{PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	s := jwtBearerServer(t, f, nil)
	// PS256 verifies with the RSA key, but the key is registered for RS256.
	signed := assertion{iss: acct.Identifier, sub: acct.Identifier, aud: s.TokenEndpointURL(), kid: k.KeyID}.sign(t, rsaKey, jose.PS256)
	code, body := postToken(t, s, jwtBearerForm(signed), true)
	if code != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Errorf("an RS256 key signing PS256 = %d %v, want invalid_grant", code, body)
	}
	if d, _ := body["error_description"].(string); !strings.Contains(d, "algorithm") {
		t.Errorf("error_description = %q, want the algorithm refusal", d)
	}
}
