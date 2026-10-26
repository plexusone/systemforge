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
// Create state manager (Secure, __Host- name, requires HTTPS)
stateManager := cfoauth.NewStateManager()

// For local development over HTTP only (logs a warning):
// stateManager := cfoauth.NewStateManagerInsecure(logger)

// At startup: refuse a configuration browsers would reject
if err := stateManager.Validate(); err != nil {
    log.Fatal(err)
}

// In redirect handler: set state cookie
func handleRedirect(w http.ResponseWriter, r *http.Request) {
    state, err := cfoauth.GenerateState()
    if err != nil {
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
    if err := stateManager.SetStateCookie(w, state); err != nil {
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }

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

The state cookie is always HttpOnly, `SameSite=Lax`, `Path=/` and
host-only. Fields left out of a hand-built `StateManager{}` take the secure
defaults, so a zero value writes the same cookie as `NewStateManager()`:

| Mode | Name | Secure | SameSite |
|------|------|--------|----------|
| Default | `__Host-sf_oauth_client_state` (`StateCookieName`) | Yes | Lax |
| `AllowInsecure` (development) | `sf_oauth_client_state` (`InsecureStateCookieName`) | No | Lax |

`SameSite` must be Lax: Strict would drop the cookie on the provider's
cross-site redirect back to the callback, and None would send it with every
cross-site request. `Validate`, `SetStateCookie` and `ValidateState` refuse
SameSite Strict or None, a negative `MaxAge`, and a `__Host-` or
`__Secure-` name without Secure (`ErrInvalidStateCookieConfig`). The
cookie is Secure unless `AllowInsecure` is set; `NewStateManagerInsecure`
sets it and logs a warning when it is called.

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
    state, err := cfoauth.GenerateState()
    if err == nil {
        err = h.stateManager.SetStateCookie(w, state)
    }
    if err != nil {
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
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

## Linking Provider Logins to Principals

SystemForge keys every upstream login by its `(provider, subject)` pair and links it to a human principal as an **external identity**. `systemauth.ResolveExternalLogin` implements the account-linking rules over a `systemauth.PrincipalDirectory`:

1. If the `(provider, subject)` pair is already linked, that principal signs in, regardless of the email the provider reports today.
2. Otherwise a **verified** upstream email links to an existing principal whose own email is also verified.
3. Otherwise a new human principal is created, which requires a verified email.

An unverified email never links to or creates an account.

```go
import (
    "errors"
    "time"

    cfoauth "github.com/plexusone/systemforge/identity/oauthclient"
    "github.com/plexusone/systemforge/identity/systemauth"
)

// dir := systemauth.NewEntPrincipalDirectory(client)
func signIn(ctx context.Context, dir systemauth.PrincipalDirectory, u *cfoauth.User) (*systemauth.HumanPrincipal, error) {
    p, err := systemauth.ResolveExternalLogin(ctx, dir, systemauth.ExternalLogin{
        Provider:      u.Provider,
        Subject:       u.ProviderID,
        Email:         u.Email,
        EmailVerified: u.EmailVerified,
        Name:          u.Name,
        AvatarURL:     u.AvatarURL,
    }, time.Now())
    switch {
    case errors.Is(err, systemauth.ErrEmailNotVerified):
        // The provider did not assert a verified email; ask the user to verify it.
    case errors.Is(err, systemauth.ErrEmailConflict):
        // An account with this email exists but cannot be linked automatically.
    case errors.Is(err, systemauth.ErrPrincipalInactive):
        // The principal is deactivated.
    }
    return p, err
}
```

The returned `HumanPrincipal.ID` is the principal ID to issue tokens for. `NewEntPrincipalDirectory` stores principals in `sf_principals` and `sf_humans` and links in `sf_external_identities`; `NewMemoryPrincipalDirectory` is available for development and tests. SystemAuth's built-in social login uses this same resolver, so a person who signs in through your application and through SystemAuth resolves to one principal.

## Security Considerations

1. **Always validate state** - Use `StateManager` or your own CSRF protection
2. **Use HTTPS in production** - the state cookie is Secure with a `__Host-` name unless `AllowInsecure` is set; only use `NewStateManagerInsecure(logger)` for local HTTP development
3. **Store tokens securely** - Encrypt any provider tokens you keep at rest
4. **Validate email ownership** - Key accounts by `Provider` + `ProviderID`; only use `Email` to link to an existing account when `EmailVerified` is true
5. **Check token expiry** - Refresh tokens before they expire

## Next Steps

- [Organizations](organizations.md) - Multi-tenant user management
- [API Keys](api-keys.md) - Server-to-server authentication
- [Authorization](../authorization/integration.md) - SpiceDB integration
