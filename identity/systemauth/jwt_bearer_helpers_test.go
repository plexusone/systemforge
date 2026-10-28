package systemauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
)

// assertion describes a JWT-bearer assertion to sign. Zero times default
// to now (iat) and a minute from now (exp); an empty jti is random unless
// noJTI is set.
type assertion struct {
	iss, sub, aud, kid, jti string
	iat, exp                time.Time
	noJTI, noIAT            bool
}

// sign signs a with key using alg.
func (a assertion) sign(t *testing.T, key crypto.Signer, alg jose.SignatureAlgorithm) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if a.kid != "" {
		opts = opts.WithHeader("kid", a.kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if a.iat.IsZero() {
		a.iat = now
	}
	if a.exp.IsZero() {
		a.exp = now.Add(time.Minute)
	}
	claims := map[string]any{"iss": a.iss, "sub": a.sub, "aud": a.aud, "exp": a.exp.Unix()}
	if !a.noIAT {
		claims["iat"] = a.iat.Unix()
	}
	if !a.noJTI {
		if a.jti == "" {
			a.jti = uuid.NewString()
		}
		claims["jti"] = a.jti
	}
	out, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// parsePrivateKey parses a PKCS #8 private key PEM.
func parsePrivateKey(t *testing.T, s string) *ecdsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		t.Fatal("no PEM block in the private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key is %T, want ECDSA", key)
	}
	return ec
}

// jwtBearerServer is SystemAuth on the fixture's database with the
// JWT-bearer grant enabled, JWT access tokens and the orgs claim.
func jwtBearerServer(t *testing.T, f *saFixture, mutate func(*Config)) *Server {
	t.Helper()
	cfg := Config{
		Issuer:   testIssuer,
		Features: FeatureConfig{EnableJWTAccessTokens: true},
		OAuth:    OAuthConfig{JWTBearer: JWTBearerConfig{Enabled: true}},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	s, err := NewEmbedded(cfg,
		WithStorage(NewEntStorage(f.db, WithDefaultOwner(f.owner))),
		WithOrgsSource(NewEntOrgsSource(f.db, f.roles)),
	)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

// jwtBearerForm is the token request form for a signed assertion.
func jwtBearerForm(signed string, scopes ...string) url.Values {
	form := url.Values{"grant_type": {GrantTypeJWTBearer}, "assertion": {signed}}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	return form
}

// postToken posts form to the token endpoint, with a DPoP proof by the
// test key when withProof is set.
func postToken(t *testing.T, s *Server, form url.Values, withProof bool) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.7:4711"
	if withProof {
		withTokenProof(t, req)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	body := map[string]any{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("token response %d is not JSON: %s", rec.Code, rec.Body.String())
	}
	return rec.Code, body
}
