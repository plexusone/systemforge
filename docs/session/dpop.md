# DPoP Enforcement

DPoP (RFC 9449) binds an access token to a key pair: the token carries the
key's thumbprint in its `cnf.jkt` claim, and every request must carry a proof
signed by that key. A stolen DPoP-bound token is useless without the private
key, and so is a token moved to another system. SystemForge uses DPoP by
default: SystemAuth and the `identity/oauth` provider issue DPoP-bound
tokens, and the middlewares require them. Unbound bearer tokens are a legacy
exception that must be switched on explicitly, per client at the
authorization server and per API in the middleware. SCIM tenant tokens are
the one deliberate exception by design; see
[SCIM tokens use the Bearer scheme](#scim-tokens-use-the-bearer-scheme).

## SystemAuth issues DPoP-bound tokens

Every token request to `/oauth/token` must carry a `DPoP` header with a proof
for `POST` at the token endpoint URL (the issuer plus `/oauth/token`, as
discovery advertises it), signed with ES256, ES384 or ES512, fresh (`iat`
within `dpop.proof_max_age`, default 5 minutes, plus `dpop.clock_skew`), and
with a `jti` not used before. On success:

- the access token is bound to the proof's key: a JWT access token carries
  `cnf.jkt`, introspection returns `cnf.jkt` and `token_type: DPoP`, and the
  token response says `token_type: DPoP`;
- the refresh token is bound to the same key: a refresh needs a proof by
  that key (RFC 9449 §5), and a refresh token presented without one, or with
  another key's, is refused without being spent;
- an authorization request may name the key in `dpop_jkt` (RFC 9449 §10):
  the code is then redeemed only with a proof by that key. A token request
  with no proof or another key's is refused before the code is touched, so
  the code can still be redeemed with the right proof, whatever the storage.

This applies to every grant SystemAuth supports: `authorization_code`,
`refresh_token` and `client_credentials`. A request without a valid proof
gets `400` with `error=invalid_dpop_proof`; a refresh or code bound to
another key gets `invalid_grant`.

| Setting | Default | Meaning |
|---------|---------|---------|
| `dpop.proof_max_age` | `5m` | How old a proof's `iat` may be |
| `dpop.clock_skew` | `30s` | How far in the future `iat` may be |
| `dpop.require_nonce` | `false` | Require server nonces (RFC 9449 §8): a proof without a current nonce gets `use_dpop_nonce` and a `DPoP-Nonce` header to retry with |
| `dpop.nonce_secret` | | Key of the nonces, at least 32 bytes, the same on every instance; required with `require_nonce` |
| `dpop.nonce_lifetime` | `5m` | How long a nonce is accepted |
| `dpop.replay_cache_redis_url` | | Redis shared by every instance for replay detection (`systemauthsvc`); embedded servers pass `systemauth.WithDPoPReplayCache` |
| `dpop.single_instance` | `false` | One instance serves SystemAuth, so the in-memory replay cache is enough |

Without a shared replay cache SystemAuth keeps an in-memory one, which only
suits a single instance. Outside development mode `systemauthsvc` refuses
to start unless `replay_cache_redis_url` is set, a cache is injected
(`Options.DPoPReplayCache`) or `single_instance` is `true`.

### The bearer-token exception

A client that cannot do DPoP yet may be registered with
`allow_bearer_tokens: true` (`ClientConfig.AllowBearerTokens`, the
`sf_oauth_apps.allow_bearer_tokens` column). It is a legacy exception:
such a client may call the token endpoint without a proof and gets unbound
tokens with `token_type: Bearer`; if it does send a proof, its tokens are
bound as usual. Every other client has RFC 9449's
`dpop_bound_access_tokens` set (`Client.DPoPBoundAccessTokens`). Prefer
moving the client to DPoP: a bearer token works for whoever holds it.

Outside development mode `systemauthsvc` refuses such clients: it does not
start with a statically configured one, and the token endpoint answers
`unauthorized_client` to one registered at runtime, unless
`production.allow` names `bearer_token_clients` (see
[Deploying SystemAuth](../systemauth/deployment.md#waiving-a-production-check)).

### SystemAuth's own resources

The userinfo endpoint, the memberships endpoint, the access-changes
endpoint, the introspection endpoint's token callers, `Server.Middleware`,
`BearerAccess`/`BearerPrincipal` and `TokenAuthenticator` accept a
DPoP-bound token only with `Authorization: DPoP <token>` and a proof by its
key for the request's method and URL (SystemAuth's own endpoints are
checked against the issuer URL; other routes against `dpop.resource_base_url`,
by default the issuer's origin, plus the request path; see
[The proof's URL behind a proxy](#the-proofs-url-behind-a-proxy)), carrying
the token's hash (`ath`). An unbound token
is accepted only with the Bearer scheme, and never in a form body when it is
bound. Errors carry a `WWW-Authenticate: DPoP` challenge with
`error="invalid_dpop_proof"`, `invalid_token` or `use_dpop_nonce`.
Discovery advertises `dpop_signing_alg_values_supported`.

## The identity/oauth provider

`identity/oauth`, the fosite-based provider over the same applications
table (`sf_oauth_apps`), applies the same rules as SystemAuth:

- its token endpoint requires a proof for `POST` at the issuer plus
  `/oauth/token` and binds the access and refresh tokens to its key
  (`token_type: DPoP`, `cnf.jkt` in introspection and in JWT access tokens
  with `Config.JWTAccessTokens`), honours `dpop_jkt`, and needs a proof by
  the bound key to refresh;
- a client whose `sf_oauth_apps.allow_bearer_tokens` is set may call it
  without a proof and gets unbound tokens (`Client.DPoPBoundAccessTokens`
  reports false), the same legacy exception;
- `API.Middleware` and the introspection endpoint's token callers accept a
  bound token only with the DPoP scheme and a proof by its key, and an
  unbound token only as Bearer;
- discovery advertises `dpop_signing_alg_values_supported`.

`Config.DPoP` sets the proof age, clock skew, replay cache (in memory by
default; pass a shared one, such as `middleware.NewRedisReplayCache`, when
several instances serve the provider) and optional server nonces
(`dpopproof.NewNonces`). The signing key rotates N / N-1 like SystemAuth's:
`Config.KeyID` names the signing key and `Config.VerificationKeys` holds the
previous key N-1 or a pre-staged next key; the JWKS publishes them all, and a
token with any other `kid` is refused.

## SCIM tokens use the Bearer scheme

SCIM tenant tokens (`sfscim_…`, see [SCIM](../identity/scim.md)) are the
deliberate exception to DPoP: SCIM requests carry them with the `Bearer`
scheme, because the identity providers that call SCIM endpoints do not
support DPoP. A SCIM token is 256 random bits, stored only as a hash,
rotated N / N-1 so at most two are valid, and scoped to one tenant. Serve
SCIM only over TLS and behind a rate limiter.

## The proof's URL behind a proxy

A proof names the URL it is for (`htu`), and the server compares it with the
URL it expects. For SystemAuth's own endpoints that is the issuer URL plus the
endpoint path, as discovery advertises it. For every other route it is a base
URL plus the request path **as this server sees it**:

| Component | Base URL setting | Default |
|-----------|------------------|---------|
| SystemAuth `Middleware`, `BearerAccess`, `BearerPrincipal` | `dpop.resource_base_url` | the issuer's origin |
| `identity/oauth` `API.Middleware` | `WithResourceBaseURL` | the issuer's origin |
| `session/middleware.HTTPAuth` and `NewDPoPAuth`, `multiapp.AuthMiddleware` | `DPoPConfig.BaseURL` | the request's scheme and `Host` |
| `identity/relyingparty.BearerMiddleware` | `DPoPConfig.BaseURL` | the request's scheme and `Host` |

The default is the origin only, with no path. Behind a proxy that maps the
external path to another one, for example one that receives
`https://example.com/api/items` and forwards `/items`, set the base URL to
the external URL including the stripped prefix (`https://example.com/api`):
otherwise a proof for the URL the client called never matches. Forwarded
headers are never trusted.

## Relying parties and APIs

| Component | Behavior |
|-----------|----------|
| `session/middleware.HTTPAuth`, `HTTPAuthForAudience`, `HTTPAuthOptional`, `ChiAuth`, `NewDPoPAuth` | Accept a token with `cnf.jkt` only with the `DPoP` scheme and one proof that matches the request method and URI, carries the token hash (`ath`), is fresh, is signed by the bound key, and has a `jti` not seen before (`DPoPConfig.ReplayCache`). Unbound tokens are refused unless `DPoPConfig.AllowBearer` is set. |
| `session/middleware.HTTPAuthBearer`, `HTTPAuthBearerForAudience`, `HTTPAuthBearerOptional` | Legacy, explicit opt-in: accept unbound bearer tokens only, and refuse any token with `cnf.jkt`; they verify no proofs. |
| `multiapp.AuthMiddleware` | Accepts a token with `cnf.jkt` only with the `DPoP` scheme and a valid proof (`MiddlewareConfig.DPoP`, whose `ReplayCache` is required), as `HTTPAuth` does, on top of the app audience check. Unbound tokens are refused unless `DPoP.AllowBearer` is set. |
| `identity/relyingparty.BearerMiddleware` and `RequestAuthenticator` | Accept a SystemAuth access token with `cnf.jkt` only with the `DPoP` scheme and a valid proof (`BearerConfig.DPoP`, required when `Tokens` is set). A bound token presented as `Bearer` is always refused. Unbound tokens are refused unless `BearerConfig.AllowBearerTokens` is set. |
| `identity/relyingparty.Client` | Sends a proof by `Config.DPoPKey` with every token request (code exchange, refresh, client credentials), so its tokens are bound to that key, and presents them to SystemAuth's userinfo, memberships and access-changes endpoints with the DPoP scheme. It retries once with a server nonce. Give every instance that shares sessions the same key; the default is a key generated per process. |
| `session/bff` | Holds a DPoP key pair per session. The proxy sends a token issued with `token_type: DPoP` (`Session.TokenType`) with the DPoP scheme and a proof, and a token issued as `Bearer` with the Bearer scheme. The refresher proves possession of the session's existing key, since a bound refresh token needs it. |
| `identity/token.DefaultService` | Binds tokens only to a `dpopproof.Proof`, which only a `dpopproof.Checker` yields after verifying a proof, never to a thumbprint its caller supplies. A bound refresh token needs a proof by the same key. |

`identity/dpopproof` is the proof checker SystemAuth, `identity/oauth` and
`identity/token` use: signature, `typ`, algorithm, `htm`, `htu`, `iat`, `ath`, replay, server
nonces, and a refusal of proofs whose `jwk` carries a private key.

## Protecting an API

For tokens minted by `session/jwt`:

```go
auth, err := middleware.HTTPAuth(jwtService, middleware.DPoPConfig{
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
instance. `appauth` uses an in-memory cache unless `Options.ReplayCache` is
set, and logs a warning for a public URL unless `Options.SingleInstance`
declares that one instance serves the API. Set `BaseURL` behind a proxy that terminates TLS or strips a
path prefix: the proof's `htu` is compared with `BaseURL` plus the request
path, and forwarded headers are never trusted (see
[The proof's URL behind a proxy](#the-proofs-url-behind-a-proxy)).

A relying party cannot forward a caller's DPoP-bound token to SystemAuth
(for example to read memberships): only the caller holds the key.
`RemoteMemberships` then fails with `relyingparty.ErrForeignDPoPToken`, and
`ClaimsOrRemoteMemberships` falls back to the token's claims.
