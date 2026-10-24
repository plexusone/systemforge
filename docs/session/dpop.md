# DPoP Enforcement

DPoP (RFC 9449) binds an access token to a key pair: the token carries the
key's thumbprint in its `cnf.jkt` claim, and every request must carry a proof
signed by that key. A stolen DPoP-bound token is useless without the private
key. This page lists where SystemForge creates, binds and verifies DPoP, and
where it does not.

## Where DPoP is enforced

| Component | Behavior |
|-----------|----------|
| `session/middleware.HTTPAuthDPoP` / `NewDPoPAuth` | Accepts a token with `cnf.jkt` only with the `DPoP` authorization scheme and one proof that matches the request method and URI, carries the token hash (`ath`), is fresh, is signed by the bound key, and has a `jti` not seen before (`ReplayCache`). Unbound tokens are accepted with the `Bearer` scheme. |
| `session/middleware.HTTPAuth`, `HTTPAuthForAudience`, `HTTPAuthOptional` | Refuse any token with `cnf.jkt`; they verify no proofs. |
| `multiapp.AuthMiddleware` | Refuses any token with `cnf.jkt`; it verifies no proofs. |
| `identity/relyingparty.BearerMiddleware` and `RequestAuthenticator` | Refuse a SystemAuth access token with `cnf.jkt` presented as `Bearer`. With `BearerConfig.DPoP` set, accept it with the `DPoP` scheme and a valid proof, under the same checks as `HTTPAuthDPoP`. |

## Where DPoP is not enforced

- **SystemAuth does not issue DPoP-bound tokens.** Its token endpoint does
  not verify DPoP proofs and does not put `cnf.jkt` in access tokens, so
  SystemAuth access and refresh tokens are bearer tokens. The BFF sends DPoP
  proofs to the token endpoint, but they are not checked there.
- **`identity/token.DefaultService`** stores a `DPoPJKT` given by its caller
  and returns it from `Validate`, but checks no proof. `Refresh` compares the
  caller-supplied thumbprint with the stored one; the caller must have
  verified a proof for that thumbprint first.
- **`session/jwt.Service`** mints DPoP-bound tokens
  (`TokenOptions.DPoPThumbprint`) and validates their signature and claims,
  but only the middleware above verifies proofs.
- **The BFF proxy** (`session/bff`, `UseDPoP`) creates proofs for upstream
  calls with the session's key pair; verification is the upstream API's job.

## Protecting an API

For tokens minted by `session/jwt`:

```go
auth, err := middleware.HTTPAuthDPoP(jwtService, middleware.DPoPConfig{
    ReplayCache: middleware.NewRedisReplayCache(redisClient, "dpop-jti:"),
    BaseURL:     "https://api.example.com", // the scheme and host clients use
})
```

For SystemAuth access tokens in a relying party:

```go
mw := relyingparty.BearerMiddleware(relyingparty.BearerConfig{
    Tokens:     client,
    Principals: store,
    DPoP: &relyingparty.DPoPConfig{
        ReplayCache: middleware.NewRedisReplayCache(redisClient, "dpop-jti:"),
        BaseURL:     "https://api.example.com",
    },
})
```

Use a replay cache shared by every instance that serves the API
(`NewRedisReplayCache`); `NewMemoryReplayCache` only suits a single
instance. Set `BaseURL` behind a proxy that terminates TLS: the proof's
`htu` is compared with `BaseURL` plus the request path, and forwarded
headers are never trusted.
