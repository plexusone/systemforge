// Package oauthclient is SystemForge's single sanctioned package for talking to
// upstream social-login providers (GitHub, Google) and to SystemAuth as an
// OAuth client. It provides provider configuration, authorization-code
// exchange, normalized user-profile fetching (including verified-email
// detection), and CSRF state handling (cookie-bound StateManager and a
// pluggable server-side StateStore).
//
// The SystemAuth server builds its GitHub/Google login on top of this package;
// applications should federate to SystemAuth rather than wiring social login
// themselves.
package oauthclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// Provider names used in User.Provider and StateData.Provider.
const (
	// ProviderGitHub identifies GitHub.
	ProviderGitHub = "github"
	// ProviderGoogle identifies Google.
	ProviderGoogle = "google"
	// ProviderSystemAuth identifies a SystemAuth server.
	ProviderSystemAuth = "systemauth"
)

// User represents user information from an OAuth provider.
type User struct {
	// ProviderID is the unique identifier from the OAuth provider.
	ProviderID string `json:"provider_id"`

	// Provider is the name of the OAuth provider (google, github, etc.).
	Provider string `json:"provider"`

	// Email is the user's email address.
	Email string `json:"email"`

	// EmailVerified reports whether the provider asserts that the user
	// controls Email. Only a verified email may be used to link an upstream
	// identity to an existing account.
	EmailVerified bool `json:"email_verified"`

	// Name is the user's display name.
	Name string `json:"name"`

	// AvatarURL is the URL to the user's profile picture.
	AvatarURL string `json:"avatar_url,omitempty"`

	// Username is the user's username (primarily for GitHub).
	Username string `json:"username,omitempty"`

	// AccessToken is the OAuth access token.
	AccessToken string `json:"-"`

	// RefreshToken is the OAuth refresh token (if provided).
	RefreshToken string `json:"-"`

	// TokenExpiry is when the access token expires.
	TokenExpiry time.Time `json:"-"`

	// Raw contains the raw user data from the provider.
	Raw map[string]any `json:"raw,omitempty"`
}

// ProviderConfig holds OAuth configuration for a provider.
type ProviderConfig struct {
	ClientID     string
	ClientSecret string //nolint:gosec // G117: config field, not a hardcoded secret
	RedirectURL  string
	Scopes       []string
}

// Enabled returns true if the provider is configured.
func (c ProviderConfig) Enabled() bool {
	return c.ClientID != "" && c.ClientSecret != ""
}

// GoogleConfig creates an OAuth2 config for Google.
func GoogleConfig(cfg ProviderConfig) *oauth2.Config {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       scopes,
		Endpoint:     google.Endpoint,
	}
}

// GitHubConfig creates an OAuth2 config for GitHub.
func GitHubConfig(cfg ProviderConfig) *oauth2.Config {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"user:email"}
	}
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Scopes:       scopes,
		Endpoint:     github.Endpoint,
	}
}

// SystemAuthConfig holds SystemAuth OAuth configuration.
type SystemAuthConfig struct {
	ProviderConfig
	BaseURL string // SystemAuth server base URL
}

// AuthorizationURL returns the SystemAuth authorization endpoint.
func (c SystemAuthConfig) AuthorizationURL() string {
	return c.BaseURL + "/oauth/authorize"
}

// TokenURL returns the SystemAuth token endpoint.
func (c SystemAuthConfig) TokenURL() string {
	return c.BaseURL + "/oauth/token"
}

// UserInfoURL returns the SystemAuth userinfo endpoint.
func (c SystemAuthConfig) UserInfoURL() string {
	return c.BaseURL + "/oauth/userinfo"
}

// OAuth2Config creates an OAuth2 config for SystemAuth.
func (c SystemAuthConfig) OAuth2Config() *oauth2.Config {
	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  c.AuthorizationURL(),
			TokenURL: c.TokenURL(),
		},
	}
}

// FetchGoogleUser fetches user info from Google using an authorization code.
func FetchGoogleUser(ctx context.Context, cfg *oauth2.Config, code string) (*User, error) {
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}
	return fetchGoogleUser(ctx, cfg.Client(ctx, token), DefaultGoogleUserInfoURL, token)
}

// FetchGitHubUser fetches user info from GitHub using an authorization code.
func FetchGitHubUser(ctx context.Context, cfg *oauth2.Config, code string) (*User, error) {
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}
	return fetchGitHubUser(ctx, cfg.Client(ctx, token), DefaultGitHubAPIURL, token)
}

// FetchSystemAuthUser fetches user info from SystemAuth using an access token.
func FetchSystemAuthUser(ctx context.Context, cfg SystemAuthConfig, accessToken string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.UserInfoURL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req) //nolint:gosec // G704: URL comes from operator-supplied SystemAuth config
	if err != nil {
		return nil, fmt.Errorf("fetching userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	var userInfo struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Picture           string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("decoding userinfo: %w", err)
	}

	name := userInfo.Name
	if name == "" {
		name = userInfo.PreferredUsername
	}
	if name == "" {
		name = userInfo.Email
	}

	return &User{
		ProviderID:    userInfo.Sub,
		Provider:      ProviderSystemAuth,
		Email:         userInfo.Email,
		EmailVerified: userInfo.EmailVerified,
		Name:          name,
		Username:      userInfo.PreferredUsername,
		AvatarURL:     userInfo.Picture,
		AccessToken:   accessToken,
		Raw: map[string]any{
			"sub":                userInfo.Sub,
			"email":              userInfo.Email,
			"email_verified":     userInfo.EmailVerified,
			"name":               userInfo.Name,
			"preferred_username": userInfo.PreferredUsername,
			"picture":            userInfo.Picture,
		},
	}, nil
}
