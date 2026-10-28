// Package serviceclient lets a SystemAuth service account call
// SystemForge-powered APIs: it signs a short assertion with the account's
// private key, exchanges it at SystemAuth's token endpoint for a short-lived
// DPoP-bound access token (the RFC 7523 JWT-bearer grant), and sends API
// requests with that token and a DPoP proof (RFC 9449).
//
// The account and its key are set up with the service-account commands; the
// private key never leaves the workload, and SystemAuth stores only the
// public key. There is no refresh token: the client signs a new assertion a
// minute before the token expires.
package serviceclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/grokify/goauth/dpop"

	"github.com/plexusone/systemforge/identity/relyingparty"
)

// GrantType is the RFC 7523 JWT-bearer grant.
const GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

const (
	// assertionLifetime is how long a signed assertion is valid; SystemAuth
	// refuses one valid for longer than its configured maximum.
	assertionLifetime = time.Minute
	// renewBefore is how long before expiry a token is replaced.
	renewBefore = time.Minute
	// maxKeyFileSize bounds LoadPrivateKey.
	maxKeyFileSize = 64 << 10
	// maxTokenResponse bounds a token response.
	maxTokenResponse = 1 << 20
	nonceHeader      = "DPoP-Nonce"
)

// Config configures a Client.
type Config struct {
	// Issuer is SystemAuth's issuer URL (required).
	Issuer string
	// Account is the service account's identifier, the assertion's iss and
	// sub (required).
	Account string
	// KeyID is the key's ID at SystemAuth, sent as the assertion's kid
	// (required).
	KeyID string
	// PrivateKey signs assertions: a P-256 ECDSA, RSA (2048 bits or more)
	// or Ed25519 key (required). A P-256 key also signs the DPoP proofs;
	// for another kind the client makes a P-256 key for them.
	PrivateKey crypto.Signer
	// Scopes requested; empty requests all the key allows.
	Scopes []string
	// HTTPClient sends the token requests and is the base of HTTPClient.
	// Default: http.DefaultClient.
	HTTPClient *http.Client
	// Metadata is SystemAuth's provider metadata, when known; nil discovers
	// it from Issuer.
	Metadata *relyingparty.Metadata
}

// Client holds a service account's credentials and its current token.
type Client struct {
	cfg       Config
	alg       gojwt.SigningMethod
	proofKey  *dpop.KeyPair
	tokenURL  string
	http      *http.Client
	mu        sync.Mutex // guards token, expiry, nonces; held during an exchange
	token     string
	expiry    time.Time
	nonces    map[string]string
	now       func() time.Time
	exchanges int
}

// New checks the configuration, finds SystemAuth's token endpoint and
// prepares the proof key. It makes no token request.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Issuer == "" || cfg.Account == "" || cfg.KeyID == "" || cfg.PrivateKey == nil {
		return nil, errors.New("serviceclient: Issuer, Account, KeyID and PrivateKey are required")
	}
	alg, err := signingMethod(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	proofKey, err := proofKeyFor(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	md := cfg.Metadata
	if md == nil {
		if md, err = relyingparty.Discover(ctx, cfg.Issuer, hc); err != nil {
			return nil, fmt.Errorf("serviceclient: discovering SystemAuth: %w", err)
		}
	}
	if md.TokenEndpoint == "" {
		return nil, errors.New("serviceclient: SystemAuth's metadata has no token endpoint")
	}
	return &Client{
		cfg: cfg, alg: alg, proofKey: proofKey, tokenURL: md.TokenEndpoint,
		http: hc, nonces: map[string]string{}, now: time.Now,
	}, nil
}

func signingMethod(k crypto.Signer) (gojwt.SigningMethod, error) {
	switch pub := k.Public().(type) {
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P256() {
			return nil, errors.New("serviceclient: an ECDSA key must be P-256")
		}
		return gojwt.SigningMethodES256, nil
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return nil, errors.New("serviceclient: an RSA key must have at least 2048 bits")
		}
		return gojwt.SigningMethodRS256, nil
	case ed25519.PublicKey:
		return gojwt.SigningMethodEdDSA, nil
	}
	return nil, fmt.Errorf("serviceclient: unsupported key type %T", k.Public())
}

// proofKeyFor uses a P-256 assertion key for proofs too, and otherwise
// makes a P-256 key for this process.
func proofKeyFor(k crypto.Signer) (*dpop.KeyPair, error) {
	if ec, ok := k.(*ecdsa.PrivateKey); ok && ec.Curve == elliptic.P256() {
		tp, err := dpop.ComputeThumbprint(&ec.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("serviceclient: key thumbprint: %w", err)
		}
		return &dpop.KeyPair{PrivateKey: ec, Thumbprint: tp}, nil
	}
	kp, err := dpop.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("serviceclient: generating the proof key: %w", err)
	}
	return kp, nil
}

// LoadPrivateKey reads a PEM private key (PKCS #8, SEC 1 or PKCS #1) from a
// file that only its owner may read.
func LoadPrivateKey(path string) (crypto.Signer, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxKeyFileSize {
		return nil, fmt.Errorf("serviceclient: %s is not a key file", path)
	}
	if info.Mode().Perm()&0o077 != 0 && !isWindows() {
		return nil, fmt.Errorf("serviceclient: %s can be read by others; restrict it with chmod 600", path)
	}
	b, err := os.ReadFile(path) //nolint:gosec // G304: the path is the operator's configuration
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(b)
}

// ParsePrivateKey parses a PEM private key: PKCS #8, SEC 1 (EC) or PKCS #1
// (RSA).
func ParsePrivateKey(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("serviceclient: not a PEM private key")
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("serviceclient: PEM block %q is not a private key", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("serviceclient: parsing the private key: %w", err)
	}
	s, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("serviceclient: unsupported key type %T", key)
	}
	return s, nil
}

func isWindows() bool { return os.PathSeparator == '\\' }

// Token returns a valid access token, exchanging a new assertion when the
// current token expires within a minute. Concurrent callers share one
// exchange.
func (c *Client) Token(ctx context.Context) (string, error) {
	return c.tokenAfter(ctx, "")
}

// tokenAfter returns a token other than stale, which the API refused.
func (c *Client) tokenAfter(ctx context.Context, stale string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.token != stale && c.now().Add(renewBefore).Before(c.expiry) {
		return c.token, nil
	}
	tok, ttl, err := c.exchange(ctx)
	if err != nil {
		return "", err
	}
	c.token, c.expiry = tok, c.now().Add(ttl)
	c.exchanges++
	return tok, nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// exchange requests a token, retrying once with SystemAuth's nonce. c.mu is
// held.
func (c *Client) exchange(ctx context.Context) (string, time.Duration, error) {
	for attempt := 0; ; attempt++ {
		resp, nonce, err := c.requestToken(ctx)
		if err != nil {
			return "", 0, err
		}
		if resp.Error == "use_dpop_nonce" && nonce != "" && attempt == 0 {
			continue
		}
		if resp.Error != "" {
			return "", 0, fmt.Errorf("serviceclient: token request refused: %s %s", resp.Error, resp.ErrorDescription)
		}
		if resp.AccessToken == "" || !strings.EqualFold(resp.TokenType, "DPoP") {
			return "", 0, fmt.Errorf("serviceclient: token response has no DPoP-bound token (token_type %q)", resp.TokenType)
		}
		ttl := time.Duration(resp.ExpiresIn) * time.Second
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}
		return resp.AccessToken, ttl, nil
	}
}

func (c *Client) requestToken(ctx context.Context) (tr *tokenResponse, nonce string, err error) {
	assertion, err := c.assertion()
	if err != nil {
		return nil, "", err
	}
	form := url.Values{"grant_type": {GrantType}, "assertion": {assertion}}
	if len(c.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}
	origin := originOf(c.tokenURL)
	proof, err := dpop.CreateProofWithOptions(c.proofKey, http.MethodPost, c.tokenURL, dpop.ProofOptions{Nonce: c.nonces[origin]})
	if err != nil {
		return nil, "", fmt.Errorf("serviceclient: DPoP proof: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, "", fmt.Errorf("serviceclient: token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(dpop.HeaderDPoP, proof)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("serviceclient: token request: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			tr, err = nil, fmt.Errorf("serviceclient: closing the token response: %w", cerr)
		}
	}()
	nonce = resp.Header.Get(nonceHeader)
	if nonce != "" {
		c.nonces[origin] = nonce
	}
	tr = &tokenResponse{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenResponse)).Decode(tr); err != nil {
		return nil, "", fmt.Errorf("serviceclient: token response (status %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK && tr.Error == "" {
		tr.Error = fmt.Sprintf("status %d", resp.StatusCode)
	}
	return tr, nonce, nil
}

// assertion signs a self-issued JWT for the token endpoint.
func (c *Client) assertion() (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("serviceclient: assertion ID: %w", err)
	}
	now := c.now()
	tok := gojwt.NewWithClaims(c.alg, gojwt.RegisteredClaims{
		Issuer:    c.cfg.Account,
		Subject:   c.cfg.Account,
		Audience:  gojwt.ClaimStrings{c.tokenURL},
		IssuedAt:  gojwt.NewNumericDate(now),
		ExpiresAt: gojwt.NewNumericDate(now.Add(assertionLifetime)),
		ID:        hex.EncodeToString(jti),
	})
	tok.Header["kid"] = c.cfg.KeyID
	s, err := tok.SignedString(c.cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("serviceclient: signing the assertion: %w", err)
	}
	return s, nil
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}
