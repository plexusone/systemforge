// Package oauthclient provides OAuth client helpers for SystemForge applications.
// This package contains utilities for fetching user info from OAuth providers
// (Google, GitHub, SystemAuth) as part of the OAuth authorization code flow.
package oauthclient

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// User represents user information from an OAuth provider.
type User struct {
	// ProviderID is the unique identifier from the OAuth provider.
	ProviderID string `json:"provider_id"`

	// Provider is the name of the OAuth provider (google, github, etc.).
	Provider string `json:"provider"`

	// Email is the user's email address.
	Email string `json:"email"`

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
	ClientSecret string
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

	client := cfg.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, fmt.Errorf("fetching userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	var userInfo struct {
		Sub        string `json:"sub"`
		Email      string `json:"email"`
		Name       string `json:"name"`
		Picture    string `json:"picture"`
		GivenName  string `json:"given_name"`
		FamilyName string `json:"family_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("decoding userinfo: %w", err)
	}

	return &User{
		ProviderID:   userInfo.Sub,
		Provider:     "google",
		Email:        userInfo.Email,
		Name:         userInfo.Name,
		AvatarURL:    userInfo.Picture,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenExpiry:  token.Expiry,
		Raw: map[string]any{
			"sub":         userInfo.Sub,
			"email":       userInfo.Email,
			"name":        userInfo.Name,
			"picture":     userInfo.Picture,
			"given_name":  userInfo.GivenName,
			"family_name": userInfo.FamilyName,
		},
	}, nil
}

// FetchGitHubUser fetches user info from GitHub using an authorization code.
func FetchGitHubUser(ctx context.Context, cfg *oauth2.Config, code string) (*User, error) {
	token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}

	client := cfg.Client(ctx, token)

	// Fetch user profile
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("fetching user: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user request failed with status %d", resp.StatusCode)
	}

	var userInfo struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("decoding user: %w", err)
	}

	// Fetch primary email if not provided
	email := userInfo.Email
	if email == "" {
		email, err = fetchGitHubPrimaryEmail(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("fetching email: %w", err)
		}
	}

	name := userInfo.Name
	if name == "" {
		name = userInfo.Login
	}

	return &User{
		ProviderID:   fmt.Sprintf("%d", userInfo.ID),
		Provider:     "github",
		Email:        email,
		Name:         name,
		Username:     userInfo.Login,
		AvatarURL:    userInfo.AvatarURL,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenExpiry:  token.Expiry,
		Raw: map[string]any{
			"id":         userInfo.ID,
			"login":      userInfo.Login,
			"name":       userInfo.Name,
			"email":      email,
			"avatar_url": userInfo.AvatarURL,
		},
	}, nil
}

func fetchGitHubPrimaryEmail(ctx context.Context, client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("emails request failed with status %d", resp.StatusCode)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	// Find primary verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	// Fall back to any verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email, nil
		}
	}

	// Fall back to any email
	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", fmt.Errorf("no email found")
}

// FetchSystemAuthUser fetches user info from SystemAuth using an access token.
func FetchSystemAuthUser(ctx context.Context, cfg SystemAuthConfig, accessToken string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", cfg.UserInfoURL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
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
		ProviderID:  userInfo.Sub,
		Provider:    "systemauth",
		Email:       userInfo.Email,
		Name:        name,
		Username:    userInfo.PreferredUsername,
		AvatarURL:   userInfo.Picture,
		AccessToken: accessToken,
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

// State management for CSRF protection

const (
	// StateCookieName is the default name for the OAuth state cookie.
	StateCookieName = "oauth_state"
	// StateCookieMaxAge is the default max age for the state cookie (5 minutes).
	StateCookieMaxAge = 5 * 60
)

// GenerateState generates a cryptographically secure random state string.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// StateManager handles OAuth state cookie management.
type StateManager struct {
	CookieName string
	MaxAge     int
	Secure     bool // Secure flag for cookies (default: true, requires HTTPS)
	SameSite   http.SameSite
}

// NewStateManager creates a state manager with secure defaults.
// Cookies are set with Secure: true, requiring HTTPS.
// For local development over HTTP, use NewStateManagerInsecure().
func NewStateManager() *StateManager {
	return &StateManager{
		CookieName: StateCookieName,
		MaxAge:     StateCookieMaxAge,
		Secure:     true,
		SameSite:   http.SameSiteLaxMode,
	}
}

// NewStateManagerInsecure creates a state manager for local development over HTTP.
// WARNING: Only use this for local development. Never use in production.
func NewStateManagerInsecure() *StateManager {
	return &StateManager{
		CookieName: StateCookieName,
		MaxAge:     StateCookieMaxAge,
		Secure:     false,
		SameSite:   http.SameSiteLaxMode,
	}
}

// SetStateCookie sets the OAuth state cookie.
func (m *StateManager) SetStateCookie(w http.ResponseWriter, state string) {
	//nolint:gosec // G124: Cookie has HttpOnly, Secure, SameSite set from StateManager config
	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   m.MaxAge,
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: m.SameSite,
	})
}

// ValidateState validates the OAuth state against the cookie and clears it.
// Returns true if valid, false otherwise.
func (m *StateManager) ValidateState(w http.ResponseWriter, r *http.Request, state string) bool {
	cookie, err := r.Cookie(m.CookieName)
	if err != nil {
		return false
	}

	// Clear the state cookie
	//nolint:gosec // G124: Cookie has HttpOnly=true, Secure/SameSite from StateManager (default secure)
	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.Secure,
		SameSite: m.SameSite,
	})

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) == 1
}
