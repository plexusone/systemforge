// Package relyingparty lets an application federate its login to SystemAuth
// as an OpenID Connect relying party, so the application never implements
// GitHub/Google login itself.
//
// It provides:
//
//   - Client: discovery, authorization URL with state + nonce + PKCE, code
//     exchange, ID-token verification against the SystemAuth JWKS (issuer,
//     audience, nonce, expiry), UserInfo, refresh and revocation.
//   - ResolvePrincipal: find-or-create of the app-local principal keyed by
//     the OIDC sub (stored as sf_principal_id), with a verified-email linking
//     fallback, behind the storage-agnostic PrincipalStore interface.
//   - BFF: an http.Handler serving the /bff/* cookie-session surface the
//     shared frontend expects (session, current user, login, callback,
//     logout), with a server-side SessionStore.
//   - BearerMiddleware: authentication for programmatic clients using
//     SystemAuth-issued JWT access tokens (verified against the JWKS) or API
//     keys, placing an AuthenticatedPrincipal in the request context.
package relyingparty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	gojwt "github.com/golang-jwt/jwt/v5"
)

// Metadata is the subset of the SystemAuth OpenID Provider configuration
// a relying party uses.
type Metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
}

// maxDocumentSize bounds discovery, JWKS and UserInfo responses.
const maxDocumentSize = 1 << 20

// Discover fetches {issuer}/.well-known/openid-configuration and checks
// that the advertised issuer matches.
func Discover(ctx context.Context, issuer string, httpClient *http.Client) (*Metadata, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	issuer = strings.TrimRight(issuer, "/")
	var md Metadata
	if err := getJSON(ctx, httpClient, issuer+"/.well-known/openid-configuration", &md); err != nil {
		return nil, fmt.Errorf("relyingparty: discovery: %w", err)
	}
	if strings.TrimRight(md.Issuer, "/") != issuer {
		return nil, fmt.Errorf("relyingparty: discovery issuer %q does not match %q", md.Issuer, issuer)
	}
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" || md.JWKSURI == "" {
		return nil, errors.New("relyingparty: discovery document is missing required endpoints")
	}
	return &md, nil
}

func getJSON(ctx context.Context, httpClient *http.Client, url string, v any) (err error) {
	// url is the operator-configured issuer or an endpoint from its
	// discovery document.
	//nolint:gosec // G704: request targets the configured SystemAuth issuer
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req) //nolint:gosec // G704: see above
	if err != nil {
		return err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: unexpected status %d", url, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDocumentSize)).Decode(v); err != nil {
		return fmt.Errorf("GET %s: decoding: %w", url, err)
	}
	return nil
}

// KeySet caches the SystemAuth JSON Web Key Set and verifies RS256 JWT
// signatures against it. An unknown key ID triggers a (rate-limited)
// refetch, so signing-key rotation is picked up without a restart.
type KeySet struct {
	url        string
	httpClient *http.Client
	minRefresh time.Duration

	mu        sync.Mutex
	keys      *jose.JSONWebKeySet
	fetchedAt time.Time
}

// NewKeySet creates a KeySet for the JWKS at jwksURL.
func NewKeySet(jwksURL string, httpClient *http.Client) *KeySet {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &KeySet{url: jwksURL, httpClient: httpClient, minRefresh: 30 * time.Second}
}

func (k *KeySet) fetch(ctx context.Context) error {
	var set jose.JSONWebKeySet
	if err := getJSON(ctx, k.httpClient, k.url, &set); err != nil {
		return fmt.Errorf("relyingparty: fetching JWKS: %w", err)
	}
	k.keys = &set
	k.fetchedAt = time.Now()
	return nil
}

// key returns the verification key for kid, refetching the JWKS when the
// key is unknown.
func (k *KeySet) key(ctx context.Context, kid string) (any, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.keys == nil {
		if err := k.fetch(ctx); err != nil {
			return nil, err
		}
	}
	if key := k.lookup(kid); key != nil {
		return key, nil
	}
	if time.Since(k.fetchedAt) >= k.minRefresh {
		if err := k.fetch(ctx); err != nil {
			return nil, err
		}
		if key := k.lookup(kid); key != nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("relyingparty: no signing key %q in JWKS", kid)
}

func (k *KeySet) lookup(kid string) any {
	if kid == "" {
		// Without a key ID only an unambiguous single key is usable.
		if len(k.keys.Keys) == 1 {
			return k.keys.Keys[0].Key
		}
		return nil
	}
	for _, jwk := range k.keys.Key(kid) {
		if jwk.Use == "" || jwk.Use == "sig" {
			return jwk.Key
		}
	}
	return nil
}

// Verify checks raw's RS256 signature and standard time claims (exp, nbf,
// iat with a small leeway) and the issuer, decoding the payload into
// claims.
func (k *KeySet) Verify(ctx context.Context, raw, issuer string, claims gojwt.Claims) error {
	_, err := gojwt.ParseWithClaims(raw, claims, func(tok *gojwt.Token) (any, error) {
		kid, _ := tok.Header["kid"].(string)
		return k.key(ctx, kid)
	},
		gojwt.WithValidMethods([]string{"RS256"}),
		gojwt.WithIssuer(issuer),
		gojwt.WithExpirationRequired(),
		gojwt.WithIssuedAt(),
		gojwt.WithLeeway(time.Minute),
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return nil
}
