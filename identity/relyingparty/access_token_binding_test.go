package relyingparty

import (
	"errors"
	"fmt"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// signTyp signs claims with the fake SystemAuth key and a JOSE typ header.
func (f *fakeSystemAuth) signTyp(typ string, claims gojwt.MapClaims) string {
	f.t.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.kid
	tok.Header["typ"] = typ
	raw, err := tok.SignedString(f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fakeSystemAuth) accessClaims(clientID string, aud ...string) gojwt.MapClaims {
	now := time.Now()
	c := gojwt.MapClaims{
		"iss": f.srv.URL, "sub": f.subject, "client_id": clientID,
		"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(), "jti": fmt.Sprint(now.UnixNano()),
	}
	if len(aud) > 0 {
		c["aud"] = aud
	}
	return c
}

// A relying party accepts only access tokens issued to its own client by
// default: not another client's access token, and not an ID token.
func TestVerifyAccessTokenBindsToClient(t *testing.T) {
	fake := newFakeSystemAuth(t)
	client := fake.client(t)
	ctx := t.Context()

	own := fake.accessJWT(fake.subject, testClientID, nil, time.Minute)
	if _, err := client.VerifyAccessToken(ctx, own); err != nil {
		t.Fatalf("own token refused: %v", err)
	}

	tests := map[string]string{
		"another client's access token": fake.accessJWT(fake.subject, "other-app", nil, time.Minute),
		"ID token for this client":      fake.idToken("n-1"),
		"logout token":                  fake.signTyp("logout+jwt", fake.accessClaims(testClientID)),
		"unknown token type":            fake.signTyp("id_token+jwt", fake.accessClaims(testClientID)),
	}
	for name, raw := range tests {
		if _, err := client.VerifyAccessToken(ctx, raw); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: err = %v, want ErrInvalidToken", name, err)
		}
	}

	if _, err := client.VerifyAccessToken(ctx, fake.signTyp("at+jwt", fake.accessClaims(testClientID))); err != nil {
		t.Errorf("at+jwt access token refused: %v", err)
	}
}

func TestVerifyAccessTokenAcceptedClientIDs(t *testing.T) {
	fake := newFakeSystemAuth(t)
	client := fake.clientWith(t, func(c *Config) { c.AcceptedClientIDs = []string{"reporting"} })
	ctx := t.Context()

	if _, err := client.VerifyAccessToken(ctx, fake.accessJWT(fake.subject, "reporting", nil, time.Minute)); err != nil {
		t.Errorf("listed client refused: %v", err)
	}
	// The list replaces the default, so the app's own client must be listed
	// to stay accepted.
	if _, err := client.VerifyAccessToken(ctx, fake.accessJWT(fake.subject, testClientID, nil, time.Minute)); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("unlisted own client accepted: %v", err)
	}
}

// With AccessTokenAudience the app is an API for many clients: any client's
// token carrying the audience is accepted, and none without it.
func TestVerifyAccessTokenAudienceMode(t *testing.T) {
	fake := newFakeSystemAuth(t)
	client := fake.clientWith(t, func(c *Config) { c.AccessTokenAudience = "https://api.example.com" })
	ctx := t.Context()

	withAud := fake.sign(fake.accessClaims("third-party", "https://api.example.com"))
	if _, err := client.VerifyAccessToken(ctx, withAud); err != nil {
		t.Errorf("token with the audience refused: %v", err)
	}
	withoutAud := fake.sign(fake.accessClaims(testClientID))
	if _, err := client.VerifyAccessToken(ctx, withoutAud); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("token without the audience accepted: %v", err)
	}
	// An ID token whose aud is the configured audience is still refused:
	// it carries no client_id.
	idAsAPI := fake.clientWith(t, func(c *Config) { c.AccessTokenAudience = testClientID })
	if _, err := idAsAPI.VerifyAccessToken(ctx, fake.idToken("n-2")); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("ID token accepted in audience mode: %v", err)
	}
}
