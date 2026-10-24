# Token Management

This guide covers working with OAuth tokens in SystemForge.

## Token Types

| Type | Purpose | Lifetime | Storage |
|------|---------|----------|---------|
| Access Token | API authorization | 15 min (default) | Memory/DB |
| Refresh Token | Get new access tokens | 7 days (default) | Database |
| Authorization Code | Exchange for tokens | 10 min | Database |

## Token Schema

The `sf_oauth_tokens` table:

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Primary key |
| `app_id` | UUID | Issuing OAuth app |
| `user_id` | UUID | Token owner (null for client_credentials) |
| `access_token_signature` | string | SHA256 of access token |
| `refresh_token_signature` | string | SHA256 of refresh token |
| `family_id` | UUID | For rotation tracking |
| `scopes` | []string | Granted scopes |
| `access_expires_at` | time | Access token expiry |
| `refresh_expires_at` | time | Refresh token expiry |
| `revoked` | bool | Revocation status |

## Token Introspection

Validate tokens programmatically:

```bash
POST /oauth/introspect
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=eyJhbGciOiJIUzI1NiIs...
```

### Active Token Response

```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "my-app",
  "username": "user@example.com",
  "exp": 1704067200,
  "iat": 1704063600,
  "sub": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Inactive Token Response

```json
{
  "active": false
}
```

## Token Refresh

Exchange a refresh token for new tokens:

```bash
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=8xLOxBtZp8&
client_id=my-app
```

### Response

```json
{
  "access_token": "new_access_token...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "new_refresh_token...",
  "scope": "openid profile email"
}
```

## Token Revocation

Revoke a token (access or refresh):

```bash
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=8xLOxBtZp8&
token_type_hint=refresh_token
```

**Note**: Revocation always returns 200 OK, even if the token doesn't exist.

## Refresh Token Rotation

When enabled, each refresh creates a new refresh token:

```go
// Enable rotation on the app
app, _ := client.OAuthApp.Create().
    SetRefreshTokenRotation(true).
    // ...
    Save(ctx)
```

### Rotation Benefits

1. **Breach Detection**: Reusing an old refresh token indicates theft
2. **Limited Window**: Stolen tokens expire faster
3. **Audit Trail**: Each token has a family ID for tracking

### Family-Based Revocation

If a rotated token is reused, revoke the entire family:

```go
func revokeTokenFamily(ctx context.Context, familyID uuid.UUID) error {
    _, err := client.OAuthToken.Update().
        Where(oauthtoken.FamilyIDEQ(familyID)).
        SetRevoked(true).
        SetRevokedAt(time.Now()).
        SetRevokedReason("rotation_violation").
        Save(ctx)
    return err
}
```

## Token Validation Middleware

`API.Middleware` accepts an access token only when it is valid and
unrevoked, was issued to a client named with `oauth.WithAcceptedClientIDs`
that is still active, and its principal is still active (the check the
introspection endpoint applies). Pass `oauth.WithAnyClient()` instead when
every client of the server may call the API and scopes alone limit them.
`Middleware` panics when the API has neither option.

```go
import "github.com/plexusone/systemforge/identity/oauth"

func main() {
    provider, _ := oauth.NewProvider(entClient, cfg)
    api, _ := oauth.NewAPI(provider, oauth.WithAcceptedClientIDs("my-app"))

    // Protected routes
    mux := http.NewServeMux()
    mux.Handle("/api/",
        api.Middleware(
            http.HandlerFunc(apiHandler),
        ),
    )
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
    // Get user from context
    userID := oauth.UserIDFromContext(r.Context())

    // Check scopes
    if !oauth.HasScope(r.Context(), "api:write") {
        http.Error(w, "insufficient scope", http.StatusForbidden)
        return
    }

    // Handle request...
}
```

## Token Cleanup

Periodically clean expired tokens:

```go
func cleanupExpiredTokens(ctx context.Context, client *ent.Client) error {
    // Delete expired access tokens
    _, err := client.OAuthToken.Delete().
        Where(
            oauthtoken.AccessExpiresAtLT(time.Now()),
            oauthtoken.Or(
                oauthtoken.RefreshExpiresAtIsNil(),
                oauthtoken.RefreshExpiresAtLT(time.Now()),
            ),
        ).
        Exec(ctx)
    if err != nil {
        return err
    }

    // Delete expired auth codes
    _, err = client.OAuthAuthCode.Delete().
        Where(oauthauthcode.ExpiresAtLT(time.Now())).
        Exec(ctx)

    return err
}

// Run as cron job
func startCleanupJob() {
    ticker := time.NewTicker(1 * time.Hour)
    go func() {
        for range ticker.C {
            cleanupExpiredTokens(context.Background(), entClient)
        }
    }()
}
```

## Admin Token Management

### List User's Tokens

```go
tokens, err := client.OAuthToken.Query().
    Where(
        oauthtoken.UserIDEQ(userID),
        oauthtoken.RevokedEQ(false),
    ).
    WithApp().
    All(ctx)
```

### Revoke All User Tokens

```go
_, err := client.OAuthToken.Update().
    Where(oauthtoken.UserIDEQ(userID)).
    SetRevoked(true).
    SetRevokedAt(time.Now()).
    SetRevokedReason("user_logout").
    Save(ctx)
```

### Revoke All App Tokens

```go
_, err := client.OAuthToken.Update().
    Where(oauthtoken.AppIDEQ(appID)).
    SetRevoked(true).
    SetRevokedAt(time.Now()).
    SetRevokedReason("app_revoked").
    Save(ctx)
```
