# Provider Interfaces

SystemAuth defines four provider interfaces that abstract authentication and OAuth functionality. Each interface can be implemented by the embedded Fosite-based system or external services like Ory.

## Identity Provider

Manages user identities (CRUD operations).

```go
type IdentityProvider interface {
    CreateIdentity(ctx context.Context, identity *Identity) error
    GetIdentity(ctx context.Context, id uuid.UUID) (*Identity, error)
    GetIdentityByEmail(ctx context.Context, email string) (*Identity, error)
    UpdateIdentity(ctx context.Context, identity *Identity) error
    DeleteIdentity(ctx context.Context, id uuid.UUID) error
    ListIdentities(ctx context.Context, filter *IdentityFilter) ([]*Identity, error)
}
```

### Identity Structure

```go
type Identity struct {
    ID        uuid.UUID      `json:"id"`
    State     IdentityState  `json:"state"`      // active, inactive
    Traits    IdentityTraits `json:"traits"`     // email, name, etc.
    Metadata  map[string]any `json:"metadata"`
    CreatedAt time.Time      `json:"created_at"`
    UpdatedAt time.Time      `json:"updated_at"`
}

type IdentityTraits struct {
    Email         string `json:"email"`
    EmailVerified bool   `json:"email_verified"`
    Name          string `json:"name"`
    GivenName     string `json:"given_name"`
    FamilyName    string `json:"family_name"`
    Picture       string `json:"picture"`
    Locale        string `json:"locale"`
}
```

### Example Usage

```go
// Create identity
identity := &systemauth.Identity{
    State: systemauth.IdentityStateActive,
    Traits: systemauth.IdentityTraits{
        Email:     "user@example.com",
        Name:      "John Doe",
        GivenName: "John",
    },
}
err := providers.Identity.CreateIdentity(ctx, identity)

// Get by email
identity, err := providers.Identity.GetIdentityByEmail(ctx, "user@example.com")
```

---

## Authentication Provider

Manages user sessions (login, validation, revocation).

```go
type AuthenticationProvider interface {
    Authenticate(ctx context.Context, req *AuthenticateRequest) (*AuthSession, error)
    ValidateSession(ctx context.Context, sessionToken string) (*AuthSession, error)
    RefreshSession(ctx context.Context, sessionToken string) (*AuthSession, error)
    RevokeSession(ctx context.Context, sessionToken string) error
    RevokeSessions(ctx context.Context, identityID uuid.UUID) error
    ListSessions(ctx context.Context, identityID uuid.UUID) ([]*AuthSession, error)
}
```

### Authentication Methods

```go
type AuthMethod string

const (
    AuthMethodPassword AuthMethod = "password"
    AuthMethodOIDC     AuthMethod = "oidc"
    AuthMethodWebAuthn AuthMethod = "webauthn"
    AuthMethodTOTP     AuthMethod = "totp"
)
```

### Example Usage

```go
// Authenticate with password
session, err := providers.Authentication.Authenticate(ctx, &systemauth.AuthenticateRequest{
    Method:     systemauth.AuthMethodPassword,
    Identifier: "user@example.com",
    Password:   "secret",
    DeviceInfo: &systemauth.DeviceInfo{
        IPAddress: r.RemoteAddr,
        UserAgent: r.UserAgent(),
    },
})

// Validate session (in middleware)
session, err := providers.Authentication.ValidateSession(ctx, sessionToken)
if err != nil {
    // Invalid or expired session
}

// Revoke all sessions (on password change)
err := providers.Authentication.RevokeSessions(ctx, userID)
```

---

## OAuth Provider

Handles OAuth 2.0 / OpenID Connect operations.

```go
type OAuthProvider interface {
    // Token operations
    Introspect(ctx context.Context, token string, tokenTypeHint string) (*OAuthIntrospection, error)
    Revoke(ctx context.Context, token string, tokenTypeHint string) error
    UserInfo(ctx context.Context, accessToken string) (*OAuthUserInfo, error)

    // Login/Consent flow (for custom UI)
    GetLoginRequest(ctx context.Context, challenge string) (*OAuthLoginRequest, error)
    AcceptLogin(ctx context.Context, challenge string, accept *OAuthLoginAccept) (*OAuthLoginResponse, error)
    GetConsentRequest(ctx context.Context, challenge string) (*OAuthConsentRequest, error)
    AcceptConsent(ctx context.Context, challenge string, accept *OAuthConsentAccept) (*OAuthConsentResponse, error)
}
```

### Example Usage

```go
// Introspect token (validate and get info)
introspection, err := providers.OAuth.Introspect(ctx, accessToken, "access_token")
if !introspection.Active {
    // Token is invalid or expired
}

// Get user info (OIDC)
userInfo, err := providers.OAuth.UserInfo(ctx, accessToken)
fmt.Printf("User: %s <%s>\n", userInfo.Name, userInfo.Email)
```

---

## OAuth Client Store

Manages OAuth 2.0 client applications.

```go
type OAuthClientStore interface {
    CreateClient(ctx context.Context, client *OAuthClient) error
    GetClient(ctx context.Context, clientID string) (*OAuthClient, error)
    UpdateClient(ctx context.Context, client *OAuthClient) error
    DeleteClient(ctx context.Context, clientID string) error
    ListClients(ctx context.Context) ([]*OAuthClient, error)
}
```

### Client Structure

```go
type OAuthClient struct {
    ClientID      string   `json:"client_id"`
    ClientSecret  string   `json:"client_secret,omitempty"`
    ClientName    string   `json:"client_name"`
    RedirectURIs  []string `json:"redirect_uris"`
    GrantTypes    []string `json:"grant_types"`
    ResponseTypes []string `json:"response_types"`
    Scope         string   `json:"scope"`
    Public        bool     `json:"public"`  // No secret (SPA, mobile)
}
```

### Example Usage

```go
// Register OAuth client
client := &systemauth.OAuthClient{
    ClientID:      "my-app",
    ClientSecret:  "super-secret",
    ClientName:    "My Application",
    RedirectURIs:  []string{"https://app.example.com/callback"},
    GrantTypes:    []string{"authorization_code", "refresh_token"},
    ResponseTypes: []string{"code"},
    Scope:         "openid profile email",
}
err := providers.OAuthClients.CreateClient(ctx, client)

// List all clients
clients, err := providers.OAuthClients.ListClients(ctx)
```

---

## Embedded Implementations

SystemAuth provides embedded implementations for all providers:

| Interface | Implementation | Backend |
|-----------|----------------|---------|
| `IdentityProvider` | `EmbeddedIdentityProvider` | SystemAuth Storage |
| `AuthenticationProvider` | `EmbeddedAuthProvider` | In-memory sessions |
| `OAuthProvider` | `EmbeddedOAuthProvider` | Fosite |
| `OAuthClientStore` | `EmbeddedOAuthClientStore` | SystemAuth Storage |

### Creating Individual Providers

```go
storage := systemauth.NewMemoryStorage()

identityProvider := systemauth.NewEmbeddedIdentityProvider(storage)
authProvider := systemauth.NewEmbeddedAuthProvider(identityProvider,
    systemauth.WithSessionDuration(24 * time.Hour),
    systemauth.WithPasswordVerifier(myVerifier),
)
clientStore := systemauth.NewEmbeddedOAuthClientStore(storage)
```
