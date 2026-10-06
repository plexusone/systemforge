package oauthclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
)

const (
	// DefaultGitHubAPIURL is the GitHub REST API base URL.
	DefaultGitHubAPIURL = "https://api.github.com"
	// DefaultGoogleUserInfoURL is Google's OpenID Connect userinfo endpoint.
	DefaultGoogleUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
)

// ErrUnsupportedProvider is returned when a Connector names a provider this
// package cannot fetch profiles from.
var ErrUnsupportedProvider = errors.New("oauthclient: unsupported provider")

// Connector bundles everything needed to run an authorization-code login
// against one upstream provider: the OAuth2 client config, the profile API
// location, and the HTTP client used for both. Endpoints are fields so tests
// (and GitHub Enterprise / alternate Google hosts) can point them elsewhere.
type Connector struct {
	// Provider is ProviderGitHub or ProviderGoogle.
	Provider string

	// OAuth2 is the client configuration (endpoints, credentials, scopes).
	OAuth2 *oauth2.Config

	// APIURL is the GitHub API base URL (for ProviderGitHub) or the userinfo
	// endpoint URL (for ProviderGoogle).
	APIURL string

	// HTTPClient, if set, is used for the token exchange and profile calls.
	HTTPClient *http.Client
}

// NewGitHubConnector returns a Connector for github.com.
func NewGitHubConnector(cfg ProviderConfig) *Connector {
	return &Connector{
		Provider: ProviderGitHub,
		OAuth2:   GitHubConfig(cfg),
		APIURL:   DefaultGitHubAPIURL,
	}
}

// NewGoogleConnector returns a Connector for Google.
func NewGoogleConnector(cfg ProviderConfig) *Connector {
	return &Connector{
		Provider: ProviderGoogle,
		OAuth2:   GoogleConfig(cfg),
		APIURL:   DefaultGoogleUserInfoURL,
	}
}

// withHTTPClient makes the oauth2 package use c.HTTPClient when set.
func (c *Connector) withHTTPClient(ctx context.Context) context.Context {
	if c.HTTPClient != nil {
		return context.WithValue(ctx, oauth2.HTTPClient, c.HTTPClient)
	}
	return ctx
}

// AuthCodeURL returns the provider authorization URL for state.
func (c *Connector) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	return c.OAuth2.AuthCodeURL(state, opts...)
}

// Exchange trades an authorization code for a token.
func (c *Connector) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	token, err := c.OAuth2.Exchange(c.withHTTPClient(ctx), code, opts...)
	if err != nil {
		return nil, fmt.Errorf("exchanging code: %w", err)
	}
	return token, nil
}

// FetchUser fetches and normalizes the user's profile with token.
func (c *Connector) FetchUser(ctx context.Context, token *oauth2.Token) (*User, error) {
	ctx = c.withHTTPClient(ctx)
	client := c.OAuth2.Client(ctx, token)
	switch c.Provider {
	case ProviderGitHub:
		return fetchGitHubUser(ctx, client, c.APIURL, token)
	case ProviderGoogle:
		return fetchGoogleUser(ctx, client, c.APIURL, token)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedProvider, c.Provider)
	}
}

func getJSON(ctx context.Context, client *http.Client, url string, accept string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req) //nolint:gosec // G704: URL is a provider API endpoint from server config, not user input
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed with status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

const githubAccept = "application/vnd.github+json"

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func fetchGitHubUser(ctx context.Context, client *http.Client, apiURL string, token *oauth2.Token) (*User, error) {
	apiURL = strings.TrimRight(apiURL, "/")

	var profile struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := getJSON(ctx, client, apiURL+"/user", githubAccept, &profile); err != nil {
		return nil, fmt.Errorf("fetching user: %w", err)
	}

	var emails []githubEmail
	emailsErr := getJSON(ctx, client, apiURL+"/user/emails", githubAccept, &emails)

	email, verified := profile.Email, false
	if email == "" {
		// No public email: the emails endpoint is required.
		if emailsErr != nil {
			return nil, fmt.Errorf("fetching email: %w", emailsErr)
		}
		email, verified = selectGitHubEmail(emails)
		if email == "" {
			return nil, errors.New("fetching email: no email found")
		}
	} else if emailsErr == nil {
		// Public email set: it counts as verified only if GitHub says so.
		for _, e := range emails {
			if strings.EqualFold(e.Email, email) {
				verified = e.Verified
				break
			}
		}
	}
	// When the profile carries a public email and the emails endpoint failed
	// (e.g. the token lacks user:email), emailsErr is intentionally not
	// returned: the public email is still usable, and leaving verified=false
	// prevents it from being used for account linking.

	name := profile.Name
	if name == "" {
		name = profile.Login
	}

	return &User{
		ProviderID:    strconv.FormatInt(profile.ID, 10),
		Provider:      ProviderGitHub,
		Email:         email,
		EmailVerified: verified,
		Name:          name,
		Username:      profile.Login,
		AvatarURL:     profile.AvatarURL,
		AccessToken:   token.AccessToken,
		RefreshToken:  token.RefreshToken,
		TokenExpiry:   token.Expiry,
		Raw: map[string]any{
			"id":         profile.ID,
			"login":      profile.Login,
			"name":       profile.Name,
			"email":      email,
			"avatar_url": profile.AvatarURL,
		},
	}, nil
}

// selectGitHubEmail prefers the primary verified email, then any verified
// email, then the first listed email (reported as unverified).
func selectGitHubEmail(emails []githubEmail) (string, bool) {
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, true
		}
	}
	for _, e := range emails {
		if e.Verified {
			return e.Email, true
		}
	}
	if len(emails) > 0 {
		return emails[0].Email, false
	}
	return "", false
}

func fetchGoogleUser(ctx context.Context, client *http.Client, userInfoURL string, token *oauth2.Token) (*User, error) {
	var userInfo struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
	}
	if err := getJSON(ctx, client, userInfoURL, "application/json", &userInfo); err != nil {
		return nil, fmt.Errorf("fetching userinfo: %w", err)
	}

	return &User{
		ProviderID:    userInfo.Sub,
		Provider:      ProviderGoogle,
		Email:         userInfo.Email,
		EmailVerified: userInfo.EmailVerified,
		Name:          userInfo.Name,
		AvatarURL:     userInfo.Picture,
		AccessToken:   token.AccessToken,
		RefreshToken:  token.RefreshToken,
		TokenExpiry:   token.Expiry,
		Raw: map[string]any{
			"sub":            userInfo.Sub,
			"email":          userInfo.Email,
			"email_verified": userInfo.EmailVerified,
			"name":           userInfo.Name,
			"picture":        userInfo.Picture,
			"given_name":     userInfo.GivenName,
			"family_name":    userInfo.FamilyName,
		},
	}, nil
}
