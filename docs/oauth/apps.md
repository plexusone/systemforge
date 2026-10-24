# OAuth Apps

OAuth apps represent client applications that can request access to your API.

## Schema

The `sf_oauth_apps` table contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Internal ID |
| `client_id` | string | Public identifier |
| `name` | string | Display name |
| `description` | string | App description |
| `logo_url` | string | App logo |
| `app_type` | enum | web, spa, native, service, machine |
| `owner_id` | UUID | Creating user |
| `organization_id` | UUID | Owning organization |
| `redirect_uris` | []string | Allowed redirects |
| `allowed_scopes` | []string | Requestable scopes |
| `allowed_grants` | []string | Allowed grant types |
| `access_token_ttl` | int | Token lifetime (seconds) |
| `refresh_token_ttl` | int | Refresh lifetime (seconds) |
| `first_party` | bool | Skip consent screen |
| `public` | bool | No client secret |
| `active` | bool | App status |

## App Types

| Type | Description | Secret | PKCE |
|------|-------------|--------|------|
| `web` | Traditional server-rendered apps | Required | Optional |
| `spa` | Single-page JavaScript apps | None | Required |
| `native` | Mobile or desktop apps | None | Required |
| `service` | Backend services | Required | No |
| `machine` | Automated systems/CI | Required | No |

## Creating Apps

### First-Party SPA

```go
app, err := client.OAuthApp.Create().
    SetClientID(generateClientID()).
    SetName("My Frontend App").
    SetAppType("spa").
    SetPublic(true).
    SetFirstParty(true).
    SetRedirectUris([]string{
        "http://localhost:3000/callback",
        "https://app.example.com/callback",
    }).
    SetAllowedScopes([]string{"openid", "profile", "email", "api"}).
    SetAllowedGrants([]string{"authorization_code", "refresh_token"}).
    SetAllowedResponseTypes([]string{"code"}).
    SetOwnerID(adminUserID).
    Save(ctx)
```

### Third-Party Web App

```go
app, err := client.OAuthApp.Create().
    SetClientID(generateClientID()).
    SetName("Partner Integration").
    SetDescription("Integration by Acme Corp").
    SetAppType("web").
    SetPublic(false). // Requires secret
    SetFirstParty(false). // Shows consent screen
    SetRedirectUris([]string{"https://partner.com/oauth/callback"}).
    SetAllowedScopes([]string{"read:data"}).
    SetAllowedGrants([]string{"authorization_code", "refresh_token"}).
    SetOwnerID(developerUserID).
    SetOrganizationID(partnerOrgID).
    Save(ctx)

// Generate and store secret
secret := generateSecret()
hash := hashSecret(secret)

_, err = client.OAuthAppSecret.Create().
    SetAppID(app.ID).
    SetSecretHash(hash).
    SetSecretPrefix(secret[:8]).
    Save(ctx)

// Return secret to developer (only time visible)
return app, secret
```

### Service Account App

```go
app, err := client.OAuthApp.Create().
    SetClientID("my-service").
    SetName("Background Worker").
    SetAppType("service").
    SetPublic(false).
    SetAllowedScopes([]string{"admin:all"}).
    SetAllowedGrants([]string{"client_credentials"}).
    SetOwnerID(systemUserID).
    Save(ctx)
```

## Client ID Generation

Generate unique, URL-safe client IDs:

```go
import (
    "crypto/rand"
    "encoding/base64"
)

func generateClientID() string {
    b := make([]byte, 16)
    rand.Read(b)
    return base64.RawURLEncoding.EncodeToString(b)
}
```

## Secret Management

### Generate Secret

```go
func generateSecret() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.RawURLEncoding.EncodeToString(b)
}
```

### Hash Secret

The token endpoint verifies a client secret against its stored hash with
`systemauth.ClientSecretHasher`, which accepts bcrypt hashes and Argon2id
hashes in PHC string format (`$argon2id$...`). Use either:

```go
import "github.com/plexusone/systemforge/identity"

func hashSecret(secret string) (string, error) {
    return identity.HashPassword(secret, identity.DefaultArgon2idParams())
}
```

A confidential client authenticates with `client_secret_basic` or
`client_secret_post`. Only secrets that are neither revoked nor expired
are accepted.

### Rotate Secret

```go
// Generate new secret
newSecret := generateSecret()
newHash := hashSecret(newSecret)

// Add new secret (old one still works)
_, err := client.OAuthAppSecret.Create().
    SetAppID(appID).
    SetSecretHash(newHash).
    SetSecretPrefix(newSecret[:8]).
    Save(ctx)

// Later: revoke old secret
_, err = client.OAuthAppSecret.Update().
    Where(oauthappsecret.IDEQ(oldSecretID)).
    SetRevoked(true).
    SetRevokedAt(time.Now()).
    Save(ctx)
```

## Querying Apps

### By Client ID

```go
app, err := client.OAuthApp.Query().
    Where(oauthapp.ClientIDEQ("my-client-id")).
    Only(ctx)
```

### User's Apps

```go
apps, err := client.OAuthApp.Query().
    Where(oauthapp.OwnerIDEQ(userID)).
    All(ctx)
```

### Organization's Apps

```go
apps, err := client.OAuthApp.Query().
    Where(oauthapp.OrganizationIDEQ(orgID)).
    All(ctx)
```

## Token Configuration

### Custom TTLs

```go
app, err := client.OAuthApp.Create().
    // ...
    SetAccessTokenTTL(3600).      // 1 hour
    SetRefreshTokenTTL(2592000).  // 30 days
    SetRefreshTokenRotation(true).
    Save(ctx)
```

### Disable Refresh Tokens

```go
app, err := client.OAuthApp.Create().
    // ...
    SetAllowedGrants([]string{"authorization_code"}). // No refresh_token
    Save(ctx)
```

## Deactivating Apps

```go
// Soft-deactivate (tokens remain valid)
_, err := client.OAuthApp.UpdateOneID(appID).
    SetActive(false).
    Save(ctx)

// Hard revoke (invalidate all tokens)
_, err = client.OAuthApp.UpdateOneID(appID).
    SetActive(false).
    SetRevokedAt(time.Now()).
    Save(ctx)

// Also revoke all tokens
_, err = client.OAuthToken.Update().
    Where(oauthtoken.AppIDEQ(appID)).
    SetRevoked(true).
    Save(ctx)
```
