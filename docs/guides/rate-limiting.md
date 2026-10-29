# Client Addresses and Rate Limiting

SystemForge finds a request's client address with one rule, and limits
requests in layers built on that address. Both are plain `net/http`
middleware in `session/clientaddr` and `session/ratelimit`; SystemAuth
applies them itself, and an application applies them to its own routes.

## The client address

A request's direct peer is the only address a client cannot choose. Behind a
reverse proxy the peer is the proxy, and the client's address is in a header
the proxy writes. A `clientaddr.Resolver` believes that header only when the
peer is one of the **trusted proxy networks**; from any other peer the header
is ignored, because any client can send it.

```go
res, err := clientaddr.New(clientaddr.Config{
    TrustedProxies: []string{"127.0.0.1/32", "::1/128"}, // the proxy on this host
    Header:         clientaddr.HeaderXForwardedFor,       // the default
})
ip := res.ClientIP(r)
```

Two kinds of header are read:

- **`X-Forwarded-For`** (the default) is read from the right. Each trusted
  proxy appends the peer it saw, so the first address from the right that is
  not a trusted proxy is the client. Entries a client wrote at the left are
  never reached. An entry that is not an address stops the walk, and the
  peer is used.
- **A single-value header**, such as `CF-Connecting-IP`, `True-Client-IP` or
  `X-Real-IP`, holds one address set by the trusted proxy. A list or a
  repeated header is not believed.

Ports (`203.0.113.9:443`, `[2001:db8::1]:443`) are removed, and IPv4-mapped
IPv6 addresses are unmapped. Without trusted networks, the zero `Config`,
every request is attributed to its peer.

### A typical deployment

A CDN or edge proxy, then a reverse proxy on the host, then the application
on loopback. The reverse proxy sets `X-Forwarded-For` to the single client
address it took from the edge's header, so the application trusts loopback
and reads `X-Forwarded-For` (`clientaddr.LoopbackProxy()`). In SystemAuth's
configuration:

```yaml
client_address:
  trusted_proxies: ["127.0.0.1/32", "::1/128"]
  header: X-Forwarded-For
```

The reverse proxy must **replace** `X-Forwarded-For` rather than append a
client-supplied value to it, and the origin must accept traffic only from the
edge (see the [production checklist](../security/production-checklist.md#edge-and-origin)).
When the application is reached directly from the edge instead, trust the
edge's published networks and read its single-value header.

### Who uses it

| Component | Setting |
|-----------|---------|
| SystemAuth | `client_address` in the configuration, or `systemauth.WithClientAddressResolver` |
| BFF (`session/bff`) | `ClientIPConfig.Resolver` |
| `appauth` | `Options.ClientAddress` (returned by `Authenticator.ClientAddress`) |
| Rate limits | `ratelimit.PolicyConfig.Address`, `ratelimit.AddressKey` |
| API key middleware | `APIKeyMiddlewareConfig.IPExtractor: res.ClientIP` |
| SCIM tokens | `scimtoken.WithClientAddress` |

Share one `Resolver` so every part of an application agrees on who a client
is. The older settings (`ratelimit.ForwardedClientIP`, `ForwardedIPKey`,
`systemauth.WithLoginTokenClientIP`, `bff.CloudflareClientIPConfig` and the
`ClientIPConfig` trust fields) still work and are deprecated.

## Layers

| Layer | Where | Keyed by | Default |
|-------|-------|----------|---------|
| Default | outermost, every route, before authentication | client address | 300 a minute |
| Route policies | same middleware, matching paths | address, or OAuth client | see below |
| Signed-in | after authentication | principal or service account | 1200 a minute |
| Handler limits | inside handlers | what only the handler knows | see below |

### Default layer and route policies

`ratelimit.Policy` applies the default limit and the route table in one
middleware. Install it outermost:

```go
storage := ratelimit.NewMemoryStorage() // one instance; RedisStorage for several
policy, err := ratelimit.NewPolicy(ratelimit.PolicyConfig{
    Storage: storage,
    Address: res,
    Routes:  ratelimit.MergeRoutes(ratelimit.DefaultRoutes(), ratelimit.Route{
        Name: ratelimit.RouteLogin, Paths: []string{"/login*"},
        Limits: []ratelimit.RouteLimit{{Key: ratelimit.KeyAddress, Limit: ratelimit.PerMinute(60)}},
    }),
    ExemptNetworks: []string{"10.20.0.0/16"}, // back-channel callers
})
if err != nil {
    return err
}
handler := policy.Middleware()(mux)
```

The default route table (`ratelimit.DefaultRoutes`):

| Name | Paths | Limits |
|------|-------|--------|
| `token` | `/oauth/token` | 120 a minute per address; 1200 a minute per client |
| `login` | `/login*` | 120 a minute per address |
| `signup` | `/signup*` | 60 a minute per address |
| `bff_auth` | `/bff/auth/*` | 120 a minute per address |
| `health` | `/healthz`, `/readyz`, `/livez`, `/health` | exempt |
| `static` | `/static/*`, `/assets/*`, `/favicon.ico`, `/robots.txt` | exempt |
| `payment_webhook` | `/billing/webhook` | exempt: the provider calls from shared addresses |

A path ending in `*` is a prefix; the longest matching pattern wins. Routes
are matched below the mount point when the policy runs inside a mounted chi
router. Replace an entry by name with `MergeRoutes`, or add new ones. The
client key reads the HTTP Basic user name or the `client_id` form field
without consuming the body; with `PolicyConfig.KnownClient`, client IDs that
are not registered share one bucket, so made-up IDs cannot grow the storage.
A policy inside another one (an embedded SystemAuth under an application's
policy) does nothing, so a request is never counted twice.

### Signed-in callers

```go
signedIn := ratelimit.NewSignedInLimiter(storage, ratelimit.PerMinute(1200))
api := authMiddleware(signedIn.Middleware()(apiHandler))
```

It keys on the principal `requestprincipal` or the JWT middleware put in the
context, and lets anonymous requests through. With `appauth`, pass it as
`Options.SignedInRateLimit` and `Authenticator.Middleware` applies it after
authentication.

### Handler limits

Some limits need the request's outcome, or a key only the handler knows.
They use the same storage through `ratelimit.Check`, or `Exhausted` and
`Record` for limits that count only some outcomes. SystemAuth applies:

| Limit | Default |
|-------|---------|
| Failed client authentication at `/oauth/token`, per address and client | 20 a minute; then the pair is refused until the window ends |
| Failed client authentication, per address | 60 a minute |
| Tokens the JWT-bearer grant issues, per service account | 60 a minute |
| Social login start, and separately the callback, per address | 30 a minute |
| Login-token exchange, per address and per registered client | 60 and 600 a minute |
| Sign-up waitlist, per address and per submitted email | 20 a minute, 5 an hour |
| Sign-up code page, per address | 30 a minute |
| Claim codes and manager invitations, per caller | `managedprincipal.DefaultCodeLimit` |

## Responses

A refused request gets `429 Too Many Requests` with `Retry-After` in whole
seconds, rounded up and never below 1. Every checked response carries the
IETF `RateLimit-Policy` and `RateLimit` headers, one item per limit checked,
and the older `X-RateLimit-*` headers:

```
RateLimit-Policy: "default";q=300;w=60, "login";q=120;w=60
RateLimit: "default";r=297;t=41, "login";r=118;t=41
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 118
X-RateLimit-Reset: 1767225600
```

## Storage outages

When the storage fails, the default layer and the signed-in limit let the
request through and log the failure; the route policies and the handler
limits of the credential endpoints (token, login, sign-up) refuse with `503`.
Set `PolicyConfig.DefaultFailClosed`, or `Route.FailOpen`, to change either.
A full `MemoryStorage` (`ErrTooManyKeys`) is always a `429`, so a flood of
new addresses cannot switch limits off.

## Storage and instances

Use `ratelimit.RedisStorage` when several instances serve the same routes,
and `MemoryStorage` with one. Memory counters with several instances let each
instance allow the full limit. The packaged SystemAuth service warns at
startup in that case unless one instance is declared; it does not refuse to
start, because the limits are looser but no check is bypassed (see
[Deploying SystemAuth](../systemauth/deployment.md#rate-limits)).

## SystemAuth configuration

```yaml
client_address:
  trusted_proxies: ["127.0.0.1/32", "::1/128"]
rate_limit:
  redis_url: ${SYSTEMAUTH_RATE_LIMIT_REDIS_URL}  # several instances
  # single_instance: true                       # or one instance
  default: {requests: 300, period: 1m}
  signed_in: {requests: 1200, period: 1m}
  exempt_networks: ["10.20.0.0/16"]
  routes:
    - name: token
      paths: ["/oauth/token"]
      per_address: {requests: 60, period: 1m}
      per_client: {requests: 600, period: 1m}
```

`rate_limit.disabled: true` turns off the default layer and the route
policies, for a host that applies its own `ratelimit.Policy` in front of
SystemAuth; the handler limits stay on. An embedding application sets the
storage with `systemauth.WithRateLimitStorage`, or
`systemauthsvc.Options.RateLimitStorage`, and reads it back with
`Server.RateLimitStorage` for its own handler limits.
