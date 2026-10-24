# AI Agents (AAuth)

A SystemForge resource server — a product API — can accept requests from AI
agents alongside people. Agents authenticate with
[AAuth](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/)
(draft -11): every request carries an HTTP message signature (RFC 9421) made
with the agent's own key, plus a token in the `Signature-Key` header that
binds the key to an identity. There are no shared secrets and no per-resource
client registration.

Two packages make this work:

| Package | What it does |
|---------|--------------|
| `identity/requestprincipal` | The protocol-neutral `RequestPrincipal`, the `Authenticator` interface, and a middleware that tries authenticators in order. No protocol dependencies. |
| `identity/requestprincipal/aauthrs` | The AAuth resource-side authenticator, built on [`github.com/aauth-dev/aauth-go`](https://github.com/aauth-dev/aauth-go). The only package that imports it. |

Human credentials keep working through
`relyingparty.NewRequestAuthenticator`, which wraps the same SystemAuth access
tokens, API keys and BFF sessions as `BearerMiddleware` (see
[Relying Parties](../systemauth/relying-party.md)).

## The request principal

Every authenticator produces the same type, so handlers don't need to know
which protocol was used:

```go
p, ok := requestprincipal.FromContext(r.Context())
```

| Field | Human (relying party) | Agent (AAuth auth token) |
|-------|-----------------------|--------------------------|
| `PrincipalID` | app-local principal ID | `<ps>#<sub>`: the person the agent acts for |
| `Type` | `human`, `service`, `application` | `agent` |
| `Subject` | SystemAuth subject | the person's directed `sub` at this resource |
| `Organization` | — | `tenant` claim |
| `Actor` | — | `jkt:<agent key thumbprint>` |
| `Delegator` | — | same as `PrincipalID` |
| `Mission` | — | `mission_s256` |
| `Session` | — | the auth token's `jti` |
| `Protocol` | `session`, `oidc`, `apikey` | `aauth` |
| `Proof` | credential method, API key ID | token type, issuer, audience, `jti`, key thumbprint, `iat`/`exp`, `Signature-Input` |
| `Scopes` | token or API key scopes | granted `scope` |
| `Native` | `*relyingparty.AuthenticatedPrincipal` | `*aauth.AuthClaims` |

A Person Server's `sub` is *directed*: it is different at each resource and
unique only within that Person Server. That's why `PrincipalID` qualifies it
with the Person Server. Use `Config.Resolve` to map it to an
application principal of your own.

## The challenge sequence

The AAuth authenticator only handles requests that carry a `Signature-Key`
header. Requests without one go to the next authenticator. When no
authenticator recognizes a request, the middleware returns a 401 that
includes every authenticator's challenge:

```http
HTTP/1.1 401 Unauthorized
AAuth-Requirement: requirement=agent-token
Link: <https://api.example.com/.well-known/aauth-resource.json>; rel="aauth-resource"
WWW-Authenticate: Bearer realm="api"
```

With the default access mode (`auth-token`), an agent works through these
steps:

| Request signed with | Response |
|---------------------|----------|
| no `Signature-Key` | 401 `requirement=agent-token` (plus the bearer challenge) |
| agent token | 401 `requirement=person-token`: which person is the agent acting for? |
| person token from a trusted Person Server | 401 `requirement=auth-token; resource-token="..."` |
| auth token that grants the route's scopes | served, `RequestPrincipal{Type: agent}` |
| auth token missing a scope | 401 `requirement=auth-token` with a new resource token (step-up) |
| an invalid, expired, mis-addressed or wrongly bound token | 401 with `Signature-Error` and a problem+json body |

Draft -11 lets a resource issue a resource token only against a person token
or an auth token that it has verified. So a request signed with only an agent
token is challenged for a person token, not an auth token. The agent's
`aauth.Transport` follows all of these challenges automatically: it gets a
person token, exchanges the resource token at its Person Server, and retries.

## Wiring a resource server

```go
import (
    aauth "github.com/aauth-dev/aauth-go"

    "github.com/plexusone/systemforge/identity/relyingparty"
    "github.com/plexusone/systemforge/identity/requestprincipal"
    "github.com/plexusone/systemforge/identity/requestprincipal/aauthrs"
)

agents, err := aauthrs.New(aauthrs.Config{
    Resource:       "https://api.example.com",            // this API's identifier
    TrustedIssuers: []string{"https://agents.example.com"}, // Person/Access Server(s)
    Key:            resourceKey,                           // Ed25519 or P-256 crypto.Signer
    Scopes: func(r *http.Request) []string {               // required per route
        if r.Method == http.MethodGet {
            return []string{"things:read"}
        }
        return []string{"things:write"}
    },
    ScopeDescriptions: map[string]string{
        "things:read":  "Read your things",
        "things:write": "Create and change your things",
    },
    HTTPClient: egressClient, // no private addresses, bounded timeouts
    Limiter:    ratelimit.Per(10, time.Minute), // optional, from aauth-go/ratelimit
})
if err != nil {
    return err
}

humans := relyingparty.NewRequestAuthenticator(relyingparty.BearerConfig{
    Tokens:     client,   // *relyingparty.Client
    APIKeys:    apiKeys,  // *apikey.Service
    Principals: principals,
    Sessions:   bff,      // optional: browser sessions too
})

mux := http.NewServeMux()
agents.Register(mux) // /.well-known/aauth-resource.json and the resource JWKS (public)

protect := requestprincipal.Middleware(requestprincipal.Options{}, agents, humans)
mux.Handle("/api/", protect(apiHandler))
```

Put the AAuth authenticator first. It only acts on requests that carry a
`Signature-Key` header, so cookies and bearer tokens still reach the
relying-party authenticator. Credentials that one authenticator recognizes
and rejects are never passed to the next one.

### Configuration

| Field | Purpose |
|-------|---------|
| `Resource` | The server identifier (https, host only). It is the `aud` of the tokens this API accepts and the `iss` of the resource tokens it issues. |
| `TrustedIssuers` | The Person Servers and Access Servers whose tokens are accepted. Tokens from other issuers are refused **before** key discovery, so an attacker can't make the API fetch keys from a URL of their choosing. |
| `TrustedAgentIssuers` | Optional. The agent providers whose bare agent tokens are accepted (`agent-token` mode); others are refused before key discovery. Whether or not it is set, an agent token is accepted only when the agent identifier's domain is the issuer's host, so a provider cannot claim another domain's agents. |
| `AccessMode` | `auth-token` (default) serves only auth tokens. `person-token` also accepts person tokens, and `agent-token` also accepts bare agent tokens, in both cases only on routes that require no scopes. |
| `Scopes` | Returns the scopes a request requires. An auth token must grant all of them, and resource tokens request them. |
| `Key`, `KeyID` | Signs resource tokens. The key is published at `JWKSPath` (default `/.well-known/aauth-resource-jwks.json`). |
| `Audience` | For four-party access, the resource's Access Server. Resource tokens are addressed to it instead of to the Person Server. |
| `Resolver`, `AgentResolver`, `HTTPClient`, `JWKSCache` | Key discovery. The default is the library's JWKS resolver and cache: metadata → `jwks_uri`, cache headers honored, refreshed at most once a minute when an unknown `kid` appears. |
| `Signature` | Signature validity window, clock and extra required components. The library defaults apply when this is left zero. |
| `CheckSubject` | The resource's record check for `(iss, sub)`. |
| `Resolve` | Maps or rejects the principal after verification. A returned `*requestprincipal.Error` is sent as the response. |
| `Limiter` | Rate-limits resource-token issuance per agent key. Refused requests get a 429 with `Retry-After`. |

## What is verified

For an auth token, the authenticator calls the library's
`VerifyAndExtractAuth` and enforces the issuer allowlist:

- the token: `typ` `aa-auth+jwt`, an allowed algorithm, `dwk`, an issuer in
  `TrustedIssuers` with its key found through JWKS discovery, `aud` equal to
  `Resource`, `iat` present and not ahead of the clock by more than the
  signature window, a lifetime of one hour
  or less, `exp` in the future with no skew allowance, and `sub`, `ps` and
  `cnf.jwk` present;
- the HTTP message signature: it covers `@method`, `@authority`, `@path`
  and `signature-key`, it was made with the key in `cnf.jwk`, and its
  `created` time is inside the validity window.

Resource tokens are issued only with `IssueResourceToken`, against the
person or auth token just verified. This copies `sub`, `mission_s256` and
`tenant` and binds the agent's key with `agent_jkt`.

## Scopes and authorization

Scope checks happen during authentication: an auth token that lacks a scope
the route needs gets a step-up challenge, not a 403. Anything beyond scopes,
such as organization membership, resource ownership or SpiceDB checks, runs in
handlers or later middleware against the `RequestPrincipal`, the same way for
people and agents.
