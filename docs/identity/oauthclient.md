# OAuth Client

The `identity/oauthclient` package provides utilities for accepting OAuth logins from external providers (GitHub, Google, SystemAuth) in your application.

## Overview

This package handles the client-side of OAuth flows where your app is the **relying party** accepting logins from external identity providers. This is different from the `oauth` package which implements an OAuth **server**.

It is the single sanctioned place in SystemForge that talks to github.com and
google.com. The former `session/oauth` package was folded into it and removed.
SystemAuth's built-in GitHub/Google login (see
[SystemAuth Social Login](../systemauth/social-login.md)) is built on this
package; prefer federating to SystemAuth over wiring social login into each
application.

## Supported Providers

- **GitHub** - OAuth 2.0 with user/email scopes
- **Google** - OpenID Connect with profile scopes
- **SystemAuth** - SystemForge's identity provider

## Quick Start

### 1. Configure OAuth Provider

```go
import cfoauth "github.com/plexusone/systemforge/identity/oauthclient"

// GitHub configuration
githubCfg := cfoauth.GitHubConfig(cfoauth.ProviderConfig{
    ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
    ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
    RedirectURL:  "http://localhost:8080/auth/oauth/github/callback",
    Scopes:       []string{"read:user", "user:email"},
})

// Google configuration
googleCfg := cfoauth.GoogleConfig(cfoauth.ProviderConfig{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURL:  "http://localhost:8080/auth/oauth/google/callback",
    Scopes:       []string{"openid", "email", "profile"},
})
```

### 2. Generate State for CSRF Protection

```go
state, err := cfoauth.GenerateState()
if err != nil {
    return err
}
// Store state in session/cookie for validation in callback
```

### 3. Redirect to Provider

```go
func handleGitHubRedirect(w http.ResponseWriter, r *http.Request) {
    state, _ := cfoauth.GenerateState()
    // Store state in cookie or session

    cfg := cfoauth.GitHubConfig(providerConfig)
    redirectURL := cfg.AuthCodeURL(state)

    http.Redirect(w, r, redirectURL, http.StatusFound)
}
```

### 4. Handle Callback

```go
func handleGitHubCallback(ctx context.Context, code string) (*cfoauth.User, error) {
    cfg := cfoauth.GitHubConfig(providerConfig)

    // Exchanges code for tokens and fetches user info in one call
    user, err := cfoauth.FetchGitHubUser(ctx, cfg, code)
    if err != nil {
        return nil, err
    }

    return user, nil
}
```

## Connector

`Connector` bundles the OAuth2 config, the profile API location, and an
optional HTTP client. Endpoint fields are overridable (tests, GitHub
Enterprise):

```go
gh := cfoauth.NewGitHubConnector(cfoauth.ProviderConfig{
    ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
    ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
    RedirectURL:  "https://auth.example.com/login/github/callback",
})

verifier := oauth2.GenerateVerifier()
authURL := gh.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

// in the callback
token, err := gh.Exchange(ctx, code, oauth2.VerifierOption(verifier))
user, err := gh.FetchUser(ctx, token)
```

## User Struct

All providers return a normalized `User` struct:

```go
type User struct {
    ProviderID   string         // Unique ID from the provider
    Provider     string         // "github", "google", "systemauth"
    Email        string         // User's email address
    EmailVerified bool          // Provider asserts the user controls Email
    Name         string         // Display name
    AvatarURL    string         // Profile picture URL
    Username     string         // Username (GitHub) or empty
    AccessToken  string         // OAuth access token
    RefreshToken string         // OAuth refresh token (if provided)
    TokenExpiry  time.Time      // When access token expires
    Raw          map[string]any // Raw response data
}
```

## State Management

The package includes a `StateManager` for cookie-based CSRF protection:

```go
// Create state manager (defaults to Secure: true, requires HTTPS)
stateManager := cfoauth.NewStateManager()

// For local development over HTTP only:
// stateManager := cfoauth.NewStateManagerInsecure()

// In redirect handler: set state cookie
func handleRedirect(w http.ResponseWriter, r *http.Request) {
    state, _ := cfoauth.GenerateState()
    stateManager.SetStateCookie(w, state)

    redirectURL := oauthConfig.AuthCodeURL(state)
    http.Redirect(w, r, redirectURL, http.StatusFound)
}

// In callback handler: validate state
func handleCallback(w http.ResponseWriter, r *http.Request) {
    state := r.URL.Query().Get("state")

    if !stateManager.ValidateState(w, r, state) {
        http.Error(w, "Invalid state", http.StatusBadRequest)
        return
    }

    // State is valid, continue with code exchange...
}
```

### Server-side state store

`StateStore` keeps per-flow data (provider, validated post-login redirect,
PKCE verifier) server-side. `Take` is single-use. `MemoryStateStore` is
concurrency-safe but single-instance only; supply a shared implementation
when running multiple replicas.

```go
store := cfoauth.NewMemoryStateStore()
_ = store.Put(ctx, state, cfoauth.StateData{Provider: cfoauth.ProviderGitHub, PKCEVerifier: verifier}, 10*time.Minute)
data, err := store.Take(ctx, state) // cfoauth.ErrInvalidState if unknown/expired/reused
```

## Complete Example

```go
package main

import (
    "context"
    "net/http"

    cfoauth "github.com/plexusone/systemforge/identity/oauthclient"
)

type AuthHandler struct {
    githubConfig *oauth2.Config
    googleConfig *oauth2.Config
    stateManager *cfoauth.StateManager
    userService  *UserService
}

func NewAuthHandler(cfg *Config) *AuthHandler {
    return &AuthHandler{
        githubConfig: cfoauth.GitHubConfig(cfoauth.ProviderConfig{
            ClientID:     cfg.GitHubClientID,
            ClientSecret: cfg.GitHubClientSecret,
            RedirectURL:  cfg.GitHubCallbackURL,
            Scopes:       []string{"read:user", "user:email"},
        }),
        googleConfig: cfoauth.GoogleConfig(cfoauth.ProviderConfig{
            ClientID:     cfg.GoogleClientID,
            ClientSecret: cfg.GoogleClientSecret,
            RedirectURL:  cfg.GoogleCallbackURL,
            Scopes:       []string{"openid", "email", "profile"},
        }),
        stateManager: cfoauth.NewStateManager(), // Secure by default
    }
}

func (h *AuthHandler) GitHubRedirect(w http.ResponseWriter, r *http.Request) {
    state, _ := cfoauth.GenerateState()
    h.stateManager.SetStateCookie(w, state)
    http.Redirect(w, r, h.githubConfig.AuthCodeURL(state), http.StatusFound)
}

func (h *AuthHandler) GitHubCallback(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Validate state
    state := r.URL.Query().Get("state")
    if !h.stateManager.ValidateState(w, r, state) {
        http.Error(w, "Invalid state", http.StatusBadRequest)
        return
    }

    // Exchange code and fetch user
    code := r.URL.Query().Get("code")
    oauthUser, err := cfoauth.FetchGitHubUser(ctx, h.githubConfig, code)
    if err != nil {
        http.Error(w, "OAuth failed", http.StatusInternalServerError)
        return
    }

    // Find or create local user
    user, err := h.userService.FindOrCreateFromOAuth(ctx, oauthUser)
    if err != nil {
        http.Error(w, "User creation failed", http.StatusInternalServerError)
        return
    }

    // Generate session/JWT and redirect
    // ...
}
```

## Provider-Specific Notes

### GitHub

- Default scopes: `user:email`
- Use `read:user` for profile access without write permissions
- Email may be private; the package fetches from `/user/emails` if needed
- `EmailVerified` is set from `/user/emails`; a public profile email whose
  verification cannot be confirmed (e.g. missing `user:email` scope) is
  reported as unverified

### Google

- Uses OpenID Connect
- Default scopes: `openid`, `email`, `profile`
- `ProviderID` is the Google `sub` claim
- `EmailVerified` is the userinfo `email_verified` claim

### SystemAuth

SystemAuth is SystemForge's identity provider for SSO across SystemForge apps:

```go
ccConfig := cfoauth.SystemAuthConfig{
    ProviderConfig: cfoauth.ProviderConfig{
        ClientID:     os.Getenv("SYSTEMAUTH_CLIENT_ID"),
        ClientSecret: os.Getenv("SYSTEMAUTH_CLIENT_SECRET"),
        RedirectURL:  "http://localhost:8080/auth/oauth/systemauth/callback",
        Scopes:       []string{"openid", "profile", "email"},
    },
    BaseURL: "https://auth.example.com",
}

oauth2Config := ccConfig.OAuth2Config()
```

## Integration with Session/JWT

After OAuth callback, generate your app's session tokens:

```go
import cfjwt "github.com/plexusone/systemforge/session/jwt"

func (h *AuthHandler) GitHubCallback(w http.ResponseWriter, r *http.Request) {
    // ... OAuth validation and user fetch ...

    // Generate JWT tokens for your app
    jwtService := cfjwt.NewService(jwtConfig)
    tokens, err := jwtService.GenerateTokenPair(user.ID, user.Email, user.Username)
    if err != nil {
        return err
    }

    // Return tokens to client
    json.NewEncoder(w).Encode(map[string]any{
        "access_token":  tokens.AccessToken,
        "refresh_token": tokens.RefreshToken,
        "expires_in":    tokens.ExpiresIn,
    })
}
```

## Storing OAuth Accounts

Link OAuth accounts to local users for multiple provider support:

```go
func (s *UserService) FindOrCreateFromOAuth(ctx context.Context, oauthUser *cfoauth.User) (*User, error) {
    // Try to find existing OAuth account
    oauthAccount, err := s.db.OAuthAccount.Query().
        Where(
            oauthaccount.ProviderEQ(oauthUser.Provider),
            oauthaccount.ProviderUserIDEQ(oauthUser.ProviderID),
        ).
        WithUser().
        Only(ctx)

    if err == nil {
        // Found existing account - update tokens
        s.db.OAuthAccount.UpdateOneID(oauthAccount.ID).
            SetAccessToken(oauthUser.AccessToken).
            Save(ctx)
        return oauthAccount.Edges.User, nil
    }

    // Check if user exists by email (account linking)
    user, err := s.db.User.Query().
        Where(user.EmailEQ(oauthUser.Email)).
        Only(ctx)

    if err == nil {
        // Link OAuth account to existing user
        s.db.OAuthAccount.Create().
            SetUser(user).
            SetProvider(oauthUser.Provider).
            SetProviderUserID(oauthUser.ProviderID).
            SetAccessToken(oauthUser.AccessToken).
            Save(ctx)
        return user, nil
    }

    // Create new user and OAuth account
    user, err = s.db.User.Create().
        SetEmail(oauthUser.Email).
        SetDisplayName(oauthUser.Name).
        SetAvatarURL(oauthUser.AvatarURL).
        Save(ctx)
    if err != nil {
        return nil, err
    }

    s.db.OAuthAccount.Create().
        SetUser(user).
        SetProvider(oauthUser.Provider).
        SetProviderUserID(oauthUser.ProviderID).
        SetAccessToken(oauthUser.AccessToken).
        Save(ctx)

    return user, nil
}
```

## Security Considerations

1. **Always validate state** - Use `StateManager` or your own CSRF protection
2. **Use HTTPS in production** - `NewStateManager()` defaults to `Secure: true`; only use `NewStateManagerInsecure()` for local HTTP development
3. **Store tokens securely** - Encrypt OAuth tokens at rest
4. **Validate email ownership** - Key accounts by `Provider` + `ProviderID`; only use `Email` to link to an existing account when `EmailVerified` is true
5. **Check token expiry** - Refresh tokens before they expire

## Next Steps

- [Organizations](organizations.md) - Multi-tenant user management
- [API Keys](api-keys.md) - Server-to-server authentication
- [Authorization](../authorization/integration.md) - SpiceDB integration
