package relyingparty

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	gojwt "github.com/golang-jwt/jwt/v5"
)

const (
	testClientID = "app"
	testAppURL   = "https://app.example.com"
	testCallback = testAppURL + "/bff/auth/callback"
)

// fakeSystemAuth is a minimal SystemAuth stand-in: discovery, JWKS, token
// (code + rotating refresh), userinfo and revocation.
type fakeSystemAuth struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string

	mu        sync.Mutex
	codes     map[string]fakeCode
	refresh   map[string]bool // refresh token -> active
	access    map[string]string
	n         int
	revoked   []string
	subject   string
	email     string
	verified  bool
	name      string
	userinfo  map[string]any // overrides userinfo response when set
	idMutator func(map[string]any)
}

type fakeCode struct {
	nonce, challenge string
}

func newFakeSystemAuth(t *testing.T) *fakeSystemAuth {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSystemAuth{
		t: t, key: key, kid: "k1",
		codes: map[string]fakeCode{}, refresh: map[string]bool{}, access: map[string]string{},
		subject: "11111111-1111-1111-1111-111111111111", email: "octo@example.com", verified: true, name: "Octo Cat",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		f.json(w, http.StatusOK, map[string]any{
			"issuer":                 f.srv.URL,
			"authorization_endpoint": f.srv.URL + "/oauth/authorize",
			"token_endpoint":         f.srv.URL + "/oauth/token",
			"userinfo_endpoint":      f.srv.URL + "/oauth/userinfo",
			"jwks_uri":               f.srv.URL + "/.well-known/jwks.json",
			"revocation_endpoint":    f.srv.URL + "/oauth/revoke",
		})
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.json(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &f.key.PublicKey, KeyID: f.kid, Algorithm: "RS256", Use: "sig",
		}}})
	})
	mux.HandleFunc("POST /oauth/token", f.handleToken)
	mux.HandleFunc("GET /oauth/userinfo", f.handleUserInfo)
	mux.HandleFunc("POST /oauth/revoke", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("revoke form: %v", err)
		}
		f.mu.Lock()
		f.revoked = append(f.revoked, r.PostForm.Get("token"))
		delete(f.refresh, r.PostForm.Get("token"))
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSystemAuth) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		f.t.Errorf("encode: %v", err)
	}
}

// issueCode simulates /oauth/authorize for the parameters of authURL.
func (f *fakeSystemAuth) issueCode(nonce, challenge string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	code := fmt.Sprintf("code-%d", f.n)
	f.codes[code] = fakeCode{nonce: nonce, challenge: challenge}
	return code
}

// sign signs claims with the fake's key (or with key/kid overrides).
func (f *fakeSystemAuth) sign(claims gojwt.MapClaims) string {
	f.t.Helper()
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, claims)
	tok.Header["kid"] = f.kid
	raw, err := tok.SignedString(f.key)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fakeSystemAuth) idToken(nonce string) string {
	now := time.Now()
	claims := gojwt.MapClaims{
		"iss": f.srv.URL, "sub": f.subject, "aud": []string{testClientID},
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "auth_time": now.Unix(),
		"nonce": nonce, "email": f.email, "email_verified": f.verified, "name": f.name,
	}
	if f.idMutator != nil {
		f.idMutator(claims)
	}
	return f.sign(claims)
}

// accessJWT returns a SystemAuth-style JWT access token.
func (f *fakeSystemAuth) accessJWT(sub, clientID string, scopes []string, ttl time.Duration) string {
	now := time.Now()
	return f.sign(gojwt.MapClaims{
		"iss": f.srv.URL, "sub": sub, "client_id": clientID, "scp": scopes,
		"exp": now.Add(ttl).Unix(), "iat": now.Unix(), "jti": fmt.Sprint(now.UnixNano()),
	})
}

func (f *fakeSystemAuth) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		f.t.Errorf("token form: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.PostForm.Get("client_id") != testClientID {
		f.json(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	resp := map[string]any{"token_type": "bearer", "expires_in": 900}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		c, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			f.json(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		resp["id_token"] = f.idToken(c.nonce)
	case "refresh_token":
		rt := r.PostForm.Get("refresh_token")
		if !f.refresh[rt] {
			f.json(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		f.refresh[rt] = false
	default:
		f.json(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	f.n++
	at, rt := fmt.Sprintf("at-%d", f.n), fmt.Sprintf("rt-%d", f.n)
	f.access[at] = f.subject
	f.refresh[rt] = true
	resp["access_token"], resp["refresh_token"] = at, rt
	f.json(w, http.StatusOK, resp)
}

func (f *fakeSystemAuth) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sub, ok := f.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.userinfo != nil {
		f.json(w, http.StatusOK, f.userinfo)
		return
	}
	f.json(w, http.StatusOK, map[string]any{"sub": sub, "email": f.email, "email_verified": f.verified, "name": f.name})
}

func (f *fakeSystemAuth) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(t.Context(), Config{
		Issuer: f.srv.URL, ClientID: testClientID, RedirectURL: testCallback, HTTPClient: f.srv.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}
