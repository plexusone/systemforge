# Configuration

SystemForge is configured through Go structs and environment variables.

## OAuth Configuration

```go
import "github.com/plexusone/systemforge/identity/oauth"

cfg := &oauth.Config{
    // Required: The base URL of your OAuth server
    Issuer: "https://api.example.com",

    // Required: 32+ byte secret for HMAC token signing
    HashSecret: []byte(os.Getenv("OAUTH_SECRET")),

    // Optional: Token lifespans (defaults shown)
    AccessTokenLifespan:  15 * time.Minute,
    RefreshTokenLifespan: 7 * 24 * time.Hour,
    AuthCodeLifespan:     10 * time.Minute,

    // Required: RSA signing key, the same on every instance and across
    // restarts. AllowEphemeralKey generates one instead, for development
    // and tests only.
    PrivateKey: rsaKey,

    // Optional: key ID and the previous or pre-staged keys, for N / N-1
    // rotation (see the key rotation guide).
    KeyID:            "signing-2",
    VerificationKeys: previousKeys,
}
```

The provider issues DPoP-bound tokens: clients send a DPoP proof with every
token request and present their tokens with `Authorization: DPoP` and a
proof. `cfg.DPoP` sets the proof age, clock skew, replay cache and optional
server nonces; pass a shared replay cache when several instances serve the
provider. See [DPoP Enforcement](../session/dpop.md#the-identityoauth-provider)
and [Rotating keys and secrets](../guides/rotation.md).

## Database Configuration

SystemForge uses Ent with PostgreSQL:

```go
import "github.com/plexusone/systemforge/identity/ent"

// Connection string
dsn := fmt.Sprintf(
    "host=%s port=%d user=%s dbname=%s password=%s sslmode=%s",
    os.Getenv("DB_HOST"),
    os.Getenv("DB_PORT"),
    os.Getenv("DB_USER"),
    os.Getenv("DB_NAME"),
    os.Getenv("DB_PASSWORD"),
    os.Getenv("DB_SSLMODE"),
)

client, err := ent.Open("postgres", dsn)
```

## Environment Variables

Recommended environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@host/db` |
| `OAUTH_SECRET` | HMAC secret (32+ bytes) | Random 32-byte string |
| `OAUTH_ISSUER` | OAuth issuer URL | `https://api.example.com` |
| `ACCESS_TOKEN_TTL` | Access token lifetime | `900` (seconds) |
| `REFRESH_TOKEN_TTL` | Refresh token lifetime | `604800` (seconds) |

## Security Configuration

### PKCE Enforcement

PKCE is enforced by default for public clients. This is configured in Fosite:

```go
fositeConfig := &fosite.Config{
    EnforcePKCE:                 true,
    EnforcePKCEForPublicClients: true,
}
```

### Token Rotation

Refresh token rotation is enabled per OAuth app:

```go
app, _ := client.OAuthApp.Create().
    SetRefreshTokenRotation(true). // Enable rotation
    // ...
    Save(ctx)
```

### Password Hashing

SystemForge uses Argon2id for password hashing:

```go
import "github.com/plexusone/systemforge/identity"

// Hash a password
hash, err := identity.HashPassword("user-password")

// Verify a password
valid := identity.VerifyPassword("user-password", hash)
```

## Production Checklist

Before deploying to production:

- [ ] Use HTTPS for all endpoints
- [ ] Set strong `OAUTH_SECRET` (32+ random bytes)
- [ ] Configure proper token lifespans
- [ ] Enable database SSL (`sslmode=require`)
- [ ] Set up database connection pooling
- [ ] Configure rate limiting
- [ ] Enable audit logging
- [ ] Set up monitoring and alerting
