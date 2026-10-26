# API Reference

!!! tip "Interactive API Documentation"
    For an interactive API reference with request examples and a try-it-out feature,
    see the [Scalar API Reference](api-reference.html).

## OAuth Endpoints

### Authorization Endpoint

Initiates the authorization code flow.

```
GET /oauth/authorize
POST /oauth/authorize
```

**Query Parameters**:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `response_type` | Yes | Must be `code` |
| `client_id` | Yes | OAuth app client ID |
| `redirect_uri` | Yes | Registered redirect URI |
| `scope` | Yes | Space-separated scopes |
| `state` | Recommended | CSRF protection token |
| `code_challenge` | Public clients | PKCE challenge |
| `code_challenge_method` | With challenge | Must be `S256` |
| `nonce` | OIDC | OpenID Connect nonce |

**Success Response**: Redirect to `redirect_uri` with `code` and `state`

**Error Response**: Redirect with `error` and `error_description`

---

### Token Endpoint

Exchange authorization code or credentials for tokens. Every request
carries a DPoP proof (RFC 9449) for `POST` at this URL, and the tokens are
bound to the proof's key; only a client registered with the legacy
`allow_bearer_tokens` exception may omit it. See
[Calling APIs with DPoP](../guides/dpop-clients.md).

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded
DPoP: <proof>
```

#### Authorization Code Grant

```
grant_type=authorization_code
code=<authorization_code>
redirect_uri=<registered_uri>
client_id=<client_id>
code_verifier=<pkce_verifier>
```

#### Client Credentials Grant

```
grant_type=client_credentials
client_id=<client_id>
client_secret=<client_secret>
scope=<requested_scopes>
```

#### Refresh Token Grant

```
grant_type=refresh_token
refresh_token=<refresh_token>
client_id=<client_id>
```

**Success Response**:

```json
{
  "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 900,
  "refresh_token": "dGhp...",
  "scope": "openid profile"
}
```

**Error Response**:

```json
{
  "error": "invalid_grant",
  "error_description": "The authorization code has expired"
}
```

---

### Introspection Endpoint

Validate and get information about a token.

```
POST /oauth/introspect
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

token=<access_token>
token_type_hint=access_token
```

**Active Token Response**:

```json
{
  "active": true,
  "scope": "openid profile",
  "client_id": "my-app",
  "username": "user@example.com",
  "token_type": "DPoP",
  "cnf": {"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"},
  "exp": 1704067200,
  "iat": 1704066300,
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": ["my-app"]
}
```

**Inactive Token Response**:

```json
{
  "active": false
}
```

---

### Revocation Endpoint

Revoke an access or refresh token.

```
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

token=<token>
token_type_hint=refresh_token
```

**Response**: Always returns `200 OK`

---

### Well-Known Endpoints

#### OpenID Configuration

```
GET /.well-known/openid-configuration
```

**Response**:

```json
{
  "issuer": "https://api.example.com",
  "authorization_endpoint": "https://api.example.com/oauth/authorize",
  "token_endpoint": "https://api.example.com/oauth/token",
  "introspection_endpoint": "https://api.example.com/oauth/introspect",
  "revocation_endpoint": "https://api.example.com/oauth/revoke",
  "jwks_uri": "https://api.example.com/.well-known/jwks.json",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256"],
  "dpop_signing_alg_values_supported": ["ES256", "ES384", "ES512"]
}
```

#### JSON Web Key Set

```
GET /.well-known/jwks.json
```

**Response**:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-id",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

---

## Go API

### OAuth Provider

```go
import "github.com/plexusone/systemforge/identity/oauth"

// Create provider
cfg := oauth.DefaultConfig("https://api.example.com", []byte("secret"))
provider, err := oauth.NewProvider(entClient, cfg)

// Get Fosite provider
fosite := provider.OAuth2Provider()

// Get storage
storage := provider.Storage()

// Create session
session := provider.Session("user-id")
```

### OAuth API

```go
// Create API with Huma/Chi router
api, err := oauth.NewAPI(provider, oauth.WithAcceptedClientIDs("my-app"))

// Mount the router - all endpoints are automatically registered:
// - /oauth/authorize (GET/POST)
// - /oauth/token (POST)
// - /oauth/introspect (POST)
// - /oauth/revoke (POST)
// - /.well-known/openid-configuration (GET)
// - /.well-known/jwks.json (GET)
http.Handle("/", api.Router())

// Middleware for protected routes: accepts tokens of the accepted clients
// only, while the client and the principal are active
protected := api.Middleware(myHandler)
```

### Context Helpers

```go
import "github.com/plexusone/systemforge/identity/oauth"

// In handler after middleware
func myHandler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Get user ID
    userID := oauth.UserIDFromContext(ctx)

    // Get scopes
    scopes := oauth.ScopesFromContext(ctx)

    // Check scope
    if oauth.HasScope(ctx, "admin") {
        // Has admin scope
    }

    // Get full access request
    ar := oauth.AccessRequestFromContext(ctx)
}
```

---

## Error Codes

| Code | Description |
|------|-------------|
| `invalid_request` | Malformed request |
| `invalid_client` | Client authentication failed |
| `invalid_grant` | Invalid authorization code or refresh token |
| `unauthorized_client` | Client not authorized for grant type |
| `unsupported_grant_type` | Grant type not supported |
| `invalid_scope` | Requested scope is invalid |
| `access_denied` | User denied authorization |
| `server_error` | Internal server error |
