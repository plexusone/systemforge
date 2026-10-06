package relyingparty

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// DefaultScopes are requested when Config.Scopes is empty.
var DefaultScopes = []string{"openid", "profile", "email", "offline_access"}

// Config configures a relying-party Client.
//
//nolint:gosec // G117: Field names are OAuth 2.0 spec-compliant, not actual secrets
type Config struct {
	// Issuer is the SystemAuth issuer URL (required).
	Issuer string

	// ClientID is this application's OAuth client ID at SystemAuth
	// (required).
	ClientID string

	// ClientSecret is the client secret for confidential clients. Leave it
	// empty for public clients (PKCE is always used).
	ClientSecret string

	// RedirectURL is the absolute callback URL registered with SystemAuth,
	// e.g. https://app.example.com/bff/auth/callback (required).
	RedirectURL string

	// Scopes requested at login. Default: DefaultScopes.
	Scopes []string

	// AccessTokenAudience, when set, is required in the "aud" of JWT access
	// tokens accepted by VerifyAccessToken.
	AccessTokenAudience string

	// HTTPClient is used for all calls to SystemAuth. Default:
	// http.DefaultClient.
	HTTPClient *http.Client
}

// Client is an OpenID Connect relying-party client for SystemAuth.
type Client struct {
	cfg      Config
	metadata Metadata
	keys     *KeySet
	oauth    *oauth2.Config
	now      func() time.Time
}

// NewClient discovers SystemAuth at cfg.Issuer and returns a Client.
func NewClient(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	md, err := Discover(ctx, cfg.Issuer, cfg.HTTPClient)
	if err != nil {
		return nil, err
	}
	return NewClientWithMetadata(cfg, *md)
}

// NewClientWithMetadata returns a Client for already-known provider
// metadata (no discovery request).
func NewClientWithMetadata(cfg Config, md Metadata) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = slices.Clone(DefaultScopes)
	}
	if !slices.Contains(cfg.Scopes, "openid") {
		return nil, errors.New("relyingparty: scopes must include openid")
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	authStyle := oauth2.AuthStyleInHeader
	if cfg.ClientSecret == "" {
		authStyle = oauth2.AuthStyleInParams
	}
	return &Client{
		cfg:      cfg,
		metadata: md,
		keys:     NewKeySet(md.JWKSURI, cfg.HTTPClient),
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       cfg.Scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:   md.AuthorizationEndpoint,
				TokenURL:  md.TokenEndpoint,
				AuthStyle: authStyle,
			},
		},
		now: time.Now,
	}, nil
}

func (c Config) validate() error {
	switch {
	case c.Issuer == "":
		return errors.New("relyingparty: Issuer is required")
	case c.ClientID == "":
		return errors.New("relyingparty: ClientID is required")
	case c.RedirectURL == "":
		return errors.New("relyingparty: RedirectURL is required")
	}
	u, err := url.Parse(c.RedirectURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("relyingparty: RedirectURL must be an absolute http(s) URL: %q", c.RedirectURL)
	}
	return nil
}

// Metadata returns the provider metadata.
func (c *Client) Metadata() Metadata { return c.metadata }

// Config returns the effective configuration.
func (c *Client) Config() Config { return c.cfg }

// AuthCodeURL returns the SystemAuth authorization URL for a login with
// the given state, nonce and PKCE verifier. Pass an IDPHint option to skip
// the provider chooser.
func (c *Client) AuthCodeURL(state, nonce, verifier string, opts ...oauth2.AuthCodeOption) string {
	opts = append(opts, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce))
	return c.oauth.AuthCodeURL(state, opts...)
}

// IDPHint asks SystemAuth to sign in with the named upstream provider
// (github, google) instead of showing its chooser.
func IDPHint(provider string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("idp_hint", provider)
}

// Exchange trades an authorization code (and its PKCE verifier) for tokens.
func (c *Client) Exchange(ctx context.Context, code, verifier string) (*oauth2.Token, error) {
	tok, err := c.oauth.Exchange(c.httpContext(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("relyingparty: code exchange: %w", err)
	}
	return tok, nil
}

// Refresh exchanges a refresh token for new tokens. SystemAuth rotates
// refresh tokens: the returned token carries the replacement, and the old
// one must not be used again.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	tok, err := c.oauth.TokenSource(c.httpContext(ctx), &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return nil, fmt.Errorf("relyingparty: refresh: %w", err)
	}
	return tok, nil
}

func (c *Client) httpContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, c.cfg.HTTPClient)
}

// Revoke revokes token at SystemAuth (RFC 7009). hint is "refresh_token"
// or "access_token" (optional). Revoking a refresh token revokes its whole
// token family.
func (c *Client) Revoke(ctx context.Context, token, hint string) (err error) {
	if c.metadata.RevocationEndpoint == "" {
		return errors.New("relyingparty: SystemAuth advertises no revocation endpoint")
	}
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	if c.cfg.ClientSecret == "" {
		form.Set("client_id", c.cfg.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.metadata.RevocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	}
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("relyingparty: revoke: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if resp.StatusCode != http.StatusOK {
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if rerr != nil {
			return fmt.Errorf("relyingparty: revoke: status %d", resp.StatusCode)
		}
		return fmt.Errorf("relyingparty: revoke: status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// IDTokenClaims are the verified claims of a SystemAuth ID token.
type IDTokenClaims struct {
	gojwt.RegisteredClaims

	Nonce           string `json:"nonce,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	AuthTime        int64  `json:"auth_time,omitempty"`
	Email           string `json:"email,omitempty"`
	EmailVerified   bool   `json:"email_verified,omitempty"`
	Name            string `json:"name,omitempty"`
	Picture         string `json:"picture,omitempty"`
	SID             string `json:"sid,omitempty"`

	// Raw holds every claim of the verified token.
	Raw map[string]any `json:"-"`
}

// rawClaims decodes the payload of a token whose signature was already
// verified.
func rawClaims(raw string) (map[string]any, error) {
	mc := gojwt.MapClaims{}
	if _, _, err := gojwt.NewParser().ParseUnverified(raw, mc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return mc, nil
}

// VerifyIDToken verifies an ID token per OIDC Core §3.1.3.7: RS256
// signature against the SystemAuth JWKS, iss equal to the issuer, aud
// containing the client ID (and azp equal to it when there are several
// audiences), unexpired, and nonce equal to the one sent at login.
func (c *Client) VerifyIDToken(ctx context.Context, raw, nonce string) (*IDTokenClaims, error) {
	claims := &IDTokenClaims{}
	if err := c.keys.Verify(ctx, raw, c.cfg.Issuer, claims); err != nil {
		return nil, err
	}
	if !slices.Contains(claims.Audience, c.cfg.ClientID) {
		return nil, fmt.Errorf("%w: audience %v does not include %q", ErrInvalidToken, claims.Audience, c.cfg.ClientID)
	}
	if len(claims.Audience) > 1 && claims.AuthorizedParty != c.cfg.ClientID {
		return nil, fmt.Errorf("%w: azp %q is not this client", ErrInvalidToken, claims.AuthorizedParty)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}
	if nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return nil, fmt.Errorf("%w: nonce mismatch", ErrInvalidToken)
	}
	rc, err := rawClaims(raw)
	if err != nil {
		return nil, err
	}
	claims.Raw = rc
	return claims, nil
}

// AccessTokenClaims are the verified claims of a SystemAuth JWT access
// token (features.enable_jwt_access_tokens).
type AccessTokenClaims struct {
	gojwt.RegisteredClaims

	ClientID string   `json:"client_id,omitempty"`
	Scopes   []string `json:"scp,omitempty"`

	// Raw holds every claim of the verified token.
	Raw map[string]any `json:"-"`
}

// HasScope reports whether the token was granted scope.
func (c *AccessTokenClaims) HasScope(scope string) bool {
	return slices.Contains(c.Scopes, scope)
}

// VerifyAccessToken verifies a SystemAuth JWT access token: RS256 signature
// against the JWKS, issuer, expiry, and Config.AccessTokenAudience when
// set. Revocation is not checked (JWTs are self-contained; keep their
// lifetime short).
func (c *Client) VerifyAccessToken(ctx context.Context, raw string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	if err := c.keys.Verify(ctx, raw, c.cfg.Issuer, claims); err != nil {
		return nil, err
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}
	if aud := c.cfg.AccessTokenAudience; aud != "" && !slices.Contains(claims.Audience, aud) {
		return nil, fmt.Errorf("%w: audience %v does not include %q", ErrInvalidToken, claims.Audience, aud)
	}
	rc, err := rawClaims(raw)
	if err != nil {
		return nil, err
	}
	claims.Raw = rc
	return claims, nil
}

// UserInfo is the SystemAuth UserInfo response.
type UserInfo struct {
	Subject       string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`

	// Raw holds every returned claim.
	Raw map[string]any `json:"-"`
}

// UserInfo fetches the current claims for accessToken.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (info *UserInfo, err error) {
	if c.metadata.UserinfoEndpoint == "" {
		return nil, errors.New("relyingparty: SystemAuth advertises no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.metadata.UserinfoEndpoint, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relyingparty: userinfo: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relyingparty: userinfo: status %d (%s)", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentSize))
	if err != nil {
		return nil, fmt.Errorf("relyingparty: userinfo: reading: %w", err)
	}
	info = &UserInfo{}
	if err := json.Unmarshal(body, info); err != nil {
		return nil, fmt.Errorf("relyingparty: userinfo: decoding: %w", err)
	}
	if err := json.Unmarshal(body, &info.Raw); err != nil {
		return nil, fmt.Errorf("relyingparty: userinfo: decoding: %w", err)
	}
	return info, nil
}

// IdentityFromClaims builds the verified identity from a verified ID token and, when
// available, the UserInfo response (which must be for the same subject,
// OIDC Core §5.3.2). UserInfo values take precedence as the fresher ones.
func IdentityFromClaims(idt *IDTokenClaims, info *UserInfo) (VerifiedIdentity, error) {
	id := VerifiedIdentity{
		Subject:       idt.Subject,
		Email:         idt.Email,
		EmailVerified: idt.EmailVerified,
		Name:          idt.Name,
		Picture:       idt.Picture,
	}
	if info == nil {
		return id, nil
	}
	if info.Subject != idt.Subject {
		return VerifiedIdentity{}, fmt.Errorf("%w: userinfo sub %q does not match ID token sub %q", ErrInvalidToken, info.Subject, idt.Subject)
	}
	if info.Email != "" {
		id.Email = info.Email
		id.EmailVerified = info.EmailVerified
	}
	if info.Name != "" {
		id.Name = info.Name
	}
	if info.Picture != "" {
		id.Picture = info.Picture
	}
	return id, nil
}

// sessionClaims merges verified ID token claims with UserInfo claims (the
// latter win) for storage with a session.
func sessionClaims(idt *IDTokenClaims, info *UserInfo) map[string]any {
	out := make(map[string]any, len(idt.Raw))
	for k, v := range idt.Raw {
		out[k] = v
	}
	if info != nil {
		for k, v := range info.Raw {
			out[k] = v
		}
	}
	return out
}
