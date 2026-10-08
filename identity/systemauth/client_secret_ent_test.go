package systemauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/oauthapp"
)

const (
	confidentialID     = "web"
	confidentialSecret = "correct-horse-battery-staple"
)

func newEntTestClient(t *testing.T, name string) *ent.Client {
	t.Helper()
	client := enttest.Open(t, "sqlite3", "file:"+name+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return client
}

// newConfidentialEntServer is SystemAuth on Ent storage with one
// confidential client, as a deployment with a persistent database has.
func newConfidentialEntServer(t *testing.T, db *ent.Client) *Server {
	t.Helper()
	s, err := NewEmbedded(Config{
		Issuer: testIssuer,
		Clients: []ClientConfig{{
			ID:            confidentialID,
			Type:          "confidential",
			Name:          "Web app",
			Secret:        confidentialSecret,
			RedirectURIs:  []string{testRPCB},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
	},
		WithSessionProvider(NewDefaultSessionProvider(WithSkipConsent(true))),
		WithStorage(NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))),
	)
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	return s
}

func confidentialCode(t *testing.T, s *Server) string {
	t.Helper()
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {confidentialID},
		"redirect_uri":          {testRPCB},
		"scope":                 {"openid offline_access"},
		"state":                 {"rp-state-12345"},
		"nonce":                 {"rp-nonce-12345"},
		"code_challenge":        {testChallenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), nil)
	headerUser("3f9b7c1e-1d2a-4b8e-9c3d-5a6f7e8d9c0b")(req)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	cb, err := url.Parse(w.Header().Get("Location"))
	if err != nil || cb.Query().Get("code") == "" {
		t.Fatalf("authorize: %d %s (%s)", w.Code, w.Body.String(), w.Header().Get("Location"))
	}
	return cb.Query().Get("code")
}

// confidentialExchange redeems code, authenticating with HTTP Basic or, if
// basic is false, with client_secret_post.
func confidentialExchange(t *testing.T, s *Server, code, secret string, basic bool) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRPCB},
		"code_verifier": {testVerifier},
	}
	if !basic {
		form.Set("client_id", confidentialID)
		form.Set("client_secret", secret)
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(confidentialID, secret)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("token response not JSON (%d): %s", w.Code, w.Body.String())
	}
	return w.Code, body
}

// TestEntConfidentialClientCodeExchange: a confidential client configured
// with a secret authenticates at the token endpoint when SystemAuth stores
// its data in a database. Loading the client used to drop its secret hash,
// so every confidential client failed with invalid_client.
func TestEntConfidentialClientCodeExchange(t *testing.T) {
	s := newConfidentialEntServer(t, newEntTestClient(t, "confidential_exchange"))

	status, body := confidentialExchange(t, s, confidentialCode(t, s), confidentialSecret, true)
	if status != http.StatusOK || body["access_token"] == nil {
		t.Fatalf("client_secret_basic exchange: %d %v", status, body)
	}
	status, body = confidentialExchange(t, s, confidentialCode(t, s), "wrong-secret", true)
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("wrong secret: %d %v", status, body)
	}
}

// TestEntClientSecretRotation: the newest active secret is the client's
// secret, older active ones are accepted as rotated secrets, and revoked or
// expired secrets are not loaded.
func TestEntClientSecretRotation(t *testing.T) {
	db := newEntTestClient(t, "secret_rotation")
	ctx := context.Background()
	st := NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))
	cfg := ClientConfig{ID: confidentialID, Type: "confidential", Name: "Web app", Secret: "old-secret", RedirectURIs: []string{testRPCB}}
	c, err := NewClientFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	app, err := db.OAuthApp.Query().Where(oauthapp.ClientIDEQ(confidentialID)).Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	add := func(secret string, created time.Time, mutate func(*ent.OAuthAppSecretCreate)) {
		t.Helper()
		h, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		b := db.OAuthAppSecret.Create().SetAppID(app.ID).SetSecretHash(string(h)).SetSecretPrefix("web").SetCreatedAt(created)
		if mutate != nil {
			mutate(b)
		}
		if _, err := b.Save(ctx); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	add("new-secret", now.Add(time.Minute), nil)
	add("revoked-secret", now.Add(2*time.Minute), func(b *ent.OAuthAppSecretCreate) { b.SetRevoked(true) })
	add("expired-secret", now.Add(3*time.Minute), func(b *ent.OAuthAppSecretCreate) { b.SetExpiresAt(now.Add(-time.Hour)) })

	fc, err := st.GetClient(ctx, confidentialID)
	if err != nil {
		t.Fatal(err)
	}
	rc, ok := fc.(fosite.ClientWithSecretRotation)
	if !ok {
		t.Fatal("client does not support secret rotation")
	}
	hasher := &fosite.BCrypt{Config: &fosite.Config{}}
	matches := func(secret string) (primary, rotated bool) {
		primary = hasher.Compare(ctx, rc.GetHashedSecret(), []byte(secret)) == nil
		for _, h := range rc.GetRotatedHashes() {
			rotated = rotated || hasher.Compare(ctx, h, []byte(secret)) == nil
		}
		return primary, rotated
	}
	if p, _ := matches("new-secret"); !p {
		t.Error("the newest secret is not the client's secret")
	}
	if _, r := matches("old-secret"); !r {
		t.Error("the older active secret is not accepted as rotated")
	}
	for _, s := range []string{"revoked-secret", "expired-secret"} {
		if p, r := matches(s); p || r {
			t.Errorf("%s was loaded", s)
		}
	}

	byID, err := st.GetClientByID(ctx, confidentialID)
	if err != nil {
		t.Fatal(err)
	}
	if !byID.ValidateSecret("new-secret") || !byID.ValidateSecret("old-secret") || byID.ValidateSecret("revoked-secret") {
		t.Error("GetClientByID does not carry the active secrets")
	}
}
