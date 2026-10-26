# Client Credentials Grant

The Client Credentials grant is used for server-to-server authentication where no user is involved.

## Use Cases

- Backend services accessing APIs
- Scheduled jobs and cron tasks
- CI/CD pipelines
- Microservice communication
- Data synchronization jobs

## Flow Overview

```
┌──────────┐                              ┌──────────┐
│  Client  │  POST /oauth/token           │  Token   │
│ (Server) │ ────────────────────────────▶│ Endpoint │
│          │  client_id + client_secret   │          │
│          │◀─────────────────────────────│          │
└──────────┘  Access Token                └──────────┘
```

## Setup

### Create Service App

```go
app, err := client.OAuthApp.Create().
    SetClientID("my-backend-service").
    SetName("Backend Service").
    SetAppType("service").
    SetPublic(false).
    SetAllowedScopes([]string{"api:read", "api:write"}).
    SetAllowedGrants([]string{"client_credentials"}).
    SetAccessTokenTTL(3600). // 1 hour
    SetOwnerID(systemUserID).
    Save(ctx)

// Generate secret
secret := generateSecret()
hash := hashSecret(secret)

_, err = client.OAuthAppSecret.Create().
    SetAppID(app.ID).
    SetSecretHash(hash).
    SetSecretPrefix(secret[:8]).
    Save(ctx)
```

## Token Request

Tokens are DPoP-bound by default: every token request carries a `DPoP`
header with a proof for `POST` at the token endpoint, signed by a key the
client keeps, and the access token is bound to that key. See
[Calling APIs with DPoP](../guides/dpop-clients.md) for how to make the key
and the proofs.

### Using Basic Authentication

```bash
curl -X POST https://api.example.com/oauth/token \
  -u "my-backend-service:client_secret_here" \
  -H "DPoP: <proof>" \
  -d "grant_type=client_credentials" \
  -d "scope=api:read api:write"
```

### Using POST Body

```bash
curl -X POST https://api.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "DPoP: <proof>" \
  -d "grant_type=client_credentials" \
  -d "client_id=my-backend-service" \
  -d "client_secret=client_secret_here" \
  -d "scope=api:read api:write"
```

## Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "DPoP",
  "expires_in": 600,
  "scope": "api:read api:write"
}
```

**Note**: No refresh token is issued. Request a new access token when needed.

Present the token with `Authorization: DPoP <token>` and a new proof for
each request. A client registered with the legacy `allow_bearer_tokens`
exception may omit the proof and gets `"token_type": "Bearer"` instead.

## Go Client Example

`golang.org/x/oauth2/clientcredentials` does not send DPoP proofs. Make the
requests with `github.com/grokify/goauth/dpop`:

```go
func callAPI(ctx context.Context, secret string) error {
    key, err := dpop.GenerateKeyPair() // keep it while its tokens are in use
    if err != nil {
        return err
    }

    // Token request with a proof for POST at the token endpoint.
    tokenURL := "https://api.example.com/oauth/token"
    proof, err := dpop.CreateProof(key, http.MethodPost, tokenURL)
    if err != nil {
        return err
    }
    form := url.Values{"grant_type": {"client_credentials"}, "scope": {"api:read api:write"}}
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
    if err != nil {
        return err
    }
    req.SetBasicAuth("my-backend-service", secret)
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("DPoP", proof)
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    var tok struct {
        AccessToken string `json:"access_token"`
        ExpiresIn   int    `json:"expires_in"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
        return err
    }

    // API call: a new proof bound to the token (ath).
    apiURL := "https://api.example.com/v1/data"
    proof, err = dpop.CreateProofWithOptions(key, http.MethodGet, apiURL,
        dpop.ProofOptions{AccessToken: tok.AccessToken})
    if err != nil {
        return err
    }
    req, err = http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
    if err != nil {
        return err
    }
    req.Header.Set("Authorization", "DPoP "+tok.AccessToken)
    req.Header.Set("DPoP", proof)
    // ...
    return nil
}
```

Check the response status before decoding, and retry once with the
`DPoP-Nonce` value when the server answers `use_dpop_nonce`.

## Token Caching

Cache the token with its expiry and the key it is bound to, and request a
new one shortly before it expires. A cached token is useless without its
key, so keep both together and request a new token whenever the key
changes.

## Security Considerations

### Secret Storage

Store client secrets securely:

```go
// Environment variable
secret := os.Getenv("OAUTH_CLIENT_SECRET")

// Secrets manager (AWS, GCP, Azure)
secret, err := secretsManager.GetSecret("my-service/oauth-secret")

// Vault
secret, err := vaultClient.Read("secret/data/my-service")
```

### Secret Rotation

A client authenticates with its current secret and the one before it.
Rotate with `EntStorage.RotateClientSecret`, which issues a new secret,
keeps the previous one valid and revokes older ones:

1. Rotate, and deploy the new secret to the client
2. Confirm the client authenticates with it
3. Revoke the previous secret with `RevokeClientSecret`, or leave it for
   the next rotation

See [Rotating keys and secrets](../guides/rotation.md#oauth-client-secrets).

### Scope Limitation

Grant minimum required scopes:

```go
// Bad: overly broad
SetAllowedScopes([]string{"admin:all"})

// Good: specific scopes
SetAllowedScopes([]string{"read:orders", "write:shipments"})
```

### IP Allowlisting

Consider restricting by IP for sensitive services:

```go
func validateClientIP(r *http.Request, allowedIPs []string) bool {
    clientIP := r.RemoteAddr
    for _, allowed := range allowedIPs {
        if clientIP == allowed {
            return true
        }
    }
    return false
}
```

## Difference from API Keys

| Feature | Client Credentials | API Keys |
|---------|-------------------|----------|
| Token lifetime | Short (minutes) | Long (months) |
| Revocation | Per-token | Per-key |
| Rotation | Automatic via expiry | Manual |
| Standards | OAuth 2.0 | Custom |
| Scopes | Per-request | Per-key |
