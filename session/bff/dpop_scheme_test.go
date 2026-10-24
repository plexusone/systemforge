package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grokify/goauth/dpop"
)

// dpopSession is a session holding a DPoP key pair and an access token of
// tokenType.
func dpopSession(t *testing.T, tokenType string, withKey bool) (*Session, *dpop.KeyPair) {
	t.Helper()
	session, err := NewSession(uuid.New(), "token", "refresh", time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	session.TokenType = tokenType
	if !withKey {
		return session, nil
	}
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.SetDPoPKeyPair(kp); err != nil {
		t.Fatal(err)
	}
	return session, kp
}

// TestProxyPresentsTokensAsIssued verifies that the proxy sends a token
// issued as DPoP with the DPoP scheme and a proof by the session's key,
// and a token issued as Bearer as Bearer without a proof, even when the
// session holds a key.
func TestProxyPresentsTokensAsIssued(t *testing.T) {
	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	config := DefaultProxyConfig()
	config.TargetURL = backend.URL
	proxy, err := NewProxy(config)
	if err != nil {
		t.Fatal(err)
	}
	serve := func(session *Session) int {
		req := httptest.NewRequest(http.MethodGet, "/items", nil)
		req = req.WithContext(context.WithValue(req.Context(), ContextKeySession, session))
		rr := httptest.NewRecorder()
		proxy.Handler().ServeHTTP(rr, req)
		return rr.Code
	}

	bound, kp := dpopSession(t, "DPoP", true)
	if code := serve(bound); code != http.StatusOK {
		t.Fatalf("DPoP session: %d", code)
	}
	if got.Get("Authorization") != "DPoP token" {
		t.Errorf("DPoP session Authorization = %q", got.Get("Authorization"))
	}
	proof, err := dpop.ParseProof(got.Get("DPoP"))
	if err != nil {
		t.Fatalf("DPoP session proof: %v", err)
	}
	if proof.Thumbprint != kp.Thumbprint || proof.Claims.AccessTokenHash != dpop.ComputeAccessTokenHash("token") ||
		proof.Claims.HTTPMethod != http.MethodGet || !strings.HasSuffix(proof.Claims.HTTPURI, "/items") {
		t.Errorf("DPoP session proof claims = %+v", proof.Claims)
	}

	// A bearer token is sent as Bearer: a DPoP scheme would be refused
	// for an unbound token.
	plain, _ := dpopSession(t, "bearer", true)
	if code := serve(plain); code != http.StatusOK {
		t.Fatalf("Bearer session: %d", code)
	}
	if got.Get("Authorization") != "Bearer token" || got.Get("DPoP") != "" {
		t.Errorf("Bearer session sent %q with proof %q", got.Get("Authorization"), got.Get("DPoP"))
	}

	// A DPoP token without a key cannot be presented at all.
	keyless, _ := dpopSession(t, "DPoP", false)
	got = nil
	if code := serve(keyless); code != http.StatusOK || got.Get("Authorization") != "" {
		t.Errorf("keyless DPoP session sent %q", got.Get("Authorization"))
	}
	ctx := context.WithValue(context.Background(), ContextKeySession, keyless)
	if _, err := proxy.ProxyRequest(ctx, http.MethodGet, "/items", nil); !errors.Is(err, ErrDPoPUnavailable) {
		t.Errorf("ProxyRequest for a keyless DPoP session: %v", err)
	}
}

// TestRefresherKeepsTheBoundKey verifies that a refresh proves possession
// of the session's existing key, which a DPoP-bound refresh token needs,
// retries with a server nonce, and records the token type.
func TestRefresherKeepsTheBoundKey(t *testing.T) {
	session, kp := dpopSession(t, "DPoP", true)
	var thumbprints []string
	calls := 0
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		proof, err := dpop.ParseProof(r.Header.Get("DPoP"))
		if err != nil {
			t.Errorf("refresh without a valid proof: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		thumbprints = append(thumbprints, proof.Thumbprint)
		w.Header().Set("Content-Type", "application/json")
		if proof.Claims.Nonce != "n-1" {
			w.Header().Set("DPoP-Nonce", "n-1")
			w.WriteHeader(http.StatusBadRequest)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "use_dpop_nonce"}); err != nil {
				t.Error(err)
			}
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"access_token": "new-token", "token_type": "DPoP", "expires_in": 600, "refresh_token": "new-refresh"}); err != nil {
			t.Error(err)
		}
	}))
	defer tokenServer.Close()

	config := DefaultRefreshConfig()
	config.TokenEndpoint = tokenServer.URL
	config.ClientID = "app"
	refresher, err := NewRefresher(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := refresher.RefreshSession(context.Background(), session); err != nil {
		t.Fatalf("RefreshSession: %v", err)
	}
	if calls != 2 {
		t.Errorf("token requests = %d, want 2 (one nonce retry)", calls)
	}
	for _, tp := range thumbprints {
		if tp != kp.Thumbprint {
			t.Errorf("refresh proved key %s, want the session's %s", tp, kp.Thumbprint)
		}
	}
	if session.DPoPThumbprint != kp.Thumbprint || session.AccessToken != "new-token" || session.TokenType != TokenTypeDPoP {
		t.Errorf("session after refresh: thumbprint %s, token %s, type %s", session.DPoPThumbprint, session.AccessToken, session.TokenType)
	}
}
