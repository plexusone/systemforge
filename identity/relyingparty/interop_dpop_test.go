package relyingparty_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/grokify/goauth/dpop"
	"golang.org/x/oauth2"

	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// TestInteropDPoPWithServerNonces runs the relying-party client against a
// SystemAuth server that requires DPoP nonces: the code exchange, userinfo
// and refresh each retry with the nonce SystemAuth hands out, the tokens are
// bound to the client's key, a refresh with another key is refused, and a
// token bound to another key cannot be forwarded.
func TestInteropDPoPWithServerNonces(t *testing.T) {
	var sa *systemauth.Server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sa.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)

	const callback = "https://app.example.com/bff/auth/callback"
	var err error
	sa, err = systemauth.NewEmbedded(systemauth.Config{
		Issuer: srv.URL,
		Clients: []systemauth.ClientConfig{{
			ID: "app", Type: "public", Name: "App",
			RedirectURIs:  []string{callback},
			GrantTypes:    []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
			Scopes:        []string{"openid", "profile", "email", "offline_access"},
		}},
		Features: systemauth.FeatureConfig{RequirePKCE: true, EnableJWTAccessTokens: true},
		DPoP:     systemauth.DPoPConfig{RequireNonce: true, NonceSecret: strings.Repeat("s", 32)},
	}, systemauth.WithSessionProvider(headerSession{}))
	if err != nil {
		t.Fatal(err)
	}
	human := &systemauth.HumanPrincipal{Email: "dev@example.com", EmailVerified: true, Active: true}
	ctx := t.Context()
	if err := sa.Storage().CreateHuman(ctx, human); err != nil {
		t.Fatal(err)
	}

	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	client, err := relyingparty.NewClient(ctx, relyingparty.Config{Issuer: srv.URL, ClientID: "app", RedirectURL: callback, DPoPKey: kp})
	if err != nil {
		t.Fatal(err)
	}

	verifier := oauth2.GenerateVerifier()
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet, client.AuthCodeURL("state-12345678", "nonce-12345678", verifier), nil)
	if err != nil {
		t.Fatal(err)
	}
	authReq.Header.Set("X-Test-User", human.ID.String())
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Do(authReq)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	cb, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || cb.Query().Get("code") == "" {
		t.Fatalf("authorize: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	tok, err := client.Exchange(ctx, cb.Query().Get("code"), verifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.Type() != "DPoP" {
		t.Errorf("token_type = %q, want DPoP", tok.TokenType)
	}
	claims, err := client.VerifyAccessToken(ctx, tok.AccessToken)
	if err != nil || claims.DPoPThumbprint() != kp.Thumbprint {
		t.Fatalf("access token binding: %+v %v", claims, err)
	}
	info, err := client.UserInfo(ctx, tok.AccessToken)
	if err != nil || info.Subject != human.ID.String() {
		t.Fatalf("userinfo: %+v %v", info, err)
	}

	// Another instance with another key cannot refresh the session.
	other, err := relyingparty.NewClient(ctx, relyingparty.Config{Issuer: srv.URL, ClientID: "app", RedirectURL: callback})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Refresh(ctx, tok.RefreshToken); err == nil {
		t.Error("a refresh with another DPoP key succeeded")
	}
	// Nor present the bound token.
	if _, err := other.UserInfo(ctx, tok.AccessToken); !errors.Is(err, relyingparty.ErrForeignDPoPToken) {
		t.Errorf("userinfo with a token bound to another key: %v", err)
	}
	// The key holder refreshes.
	next, err := client.Refresh(ctx, tok.RefreshToken)
	if err != nil || next.Type() != "DPoP" || next.RefreshToken == tok.RefreshToken {
		t.Fatalf("refresh: %+v %v", next, err)
	}
}
