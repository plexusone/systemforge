# Relying Parties (Federating to SystemAuth)

Applications do not implement GitHub/Google login themselves. They federate to
SystemAuth as OpenID Connect clients with the `identity/relyingparty` package,
which provides the whole browser and API surface:

| Piece | What it does |
|-------|--------------|
| `Client` | Discovery, authorization URL (state + nonce + S256 PKCE), code exchange, ID-token verification against the SystemAuth JWKS, UserInfo, refresh, revocation |
| `ResolvePrincipal` + `PrincipalStore` | Find-or-create the app-local principal keyed by the OIDC `sub` → `sf_principal_id`, with a verified-email linking fallback |
| `BFF` | `http.Handler` for the `/bff/*` cookie-session surface the shared frontend auth package expects |
| `BearerMiddleware` | Authenticates programmatic clients (CLI, MCP, services) with SystemAuth JWT access tokens |

See ADR-002 (`docs/design/adrs/ADR-002-centralized-social-login-systemauth.md`)
for the design.

## SystemAuth setup

Register the application as a client and enable JWT access tokens if
programmatic clients will call the application with SystemAuth tokens:

```yaml
features:
  require_pkce: true
  enable_jwt_access_tokens: true   # needed by BearerMiddleware
clients:
  - id: my-app
    type: public                   # or confidential with a secret
    name: My App
    redirect_uris:
      - https://app.example.com/bff/auth/callback
    grant_types: [authorization_code, refresh_token]
    response_types: [code]
    scopes: [openid, profile, email, offline_access]
social_login:
  allowed_redirect_origins:
    - https://app.example.com
```

SystemAuth returns an RS256 `id_token` (with `nonce`, `auth_time`, and the
scope-filtered `email`, `email_verified`, `name`, `picture`), rotating refresh
tokens, and serves `/oauth/userinfo`. Every JWT carries the `kid` published in
`/.well-known/jwks.json`.

## Application setup

Most applications use [`identity/appauth`](../guides/app-authentication.md),
which assembles everything below with the defaults every SystemForge
application shares. This section shows the parts it is built from.

```go
import "github.com/plexusone/systemforge/identity/relyingparty"

client, err := relyingparty.NewClient(ctx, relyingparty.Config{
    Issuer:      "https://auth.example.com",
    ClientID:    "my-app",
    RedirectURL: "https://app.example.com/bff/auth/callback",
    // ClientSecret: os.Getenv("SYSTEMAUTH_CLIENT_SECRET"), // confidential clients
    // The key sessions' tokens are bound to. Without it a key is generated
    // per process, and every restart signs everyone out.
    DPoPKey: dpopKey, // appauth.ParseDPoPKey or appauth.ReadDPoPKeyFile
})
if err != nil {
    return err
}

principals := myapp.NewPrincipalStore(db) // implements relyingparty.PrincipalStore

bff, err := relyingparty.NewBFF(relyingparty.BFFConfig{
    Client:     client,
    Principals: principals,
    Sessions:   sessions, // e.g. pgstore.NewSessionStore; default: in-memory (single instance)
})
if err != nil {
    return err
}

r := chi.NewRouter()
r.Mount("/bff", bff)

// Browser-only routes: BFF session required.
r.With(bff.RequireSession).Get("/app/api/projects", listProjects)

// API used by browsers and programmatic clients alike.
r.Route("/api/v1", func(r chi.Router) {
    r.Use(relyingparty.BearerMiddleware(relyingparty.BearerConfig{
        Tokens:     client,         // SystemAuth JWT access tokens (DPoP-bound)
        DPoP:       &relyingparty.DPoPConfig{ReplayCache: replayCache, BaseURL: "https://app.example.com"},
        Principals: principals,
        Sessions:   bff,            // also accept the BFF cookie
    }))
    r.Get("/projects", listProjects)
})

func listProjects(w http.ResponseWriter, r *http.Request) {
    p, _ := relyingparty.PrincipalFromContext(r.Context())
    // p.ID, p.Type, p.Subject, p.Method, p.Scopes, p.Memberships
}
```

## `/bff/*` contract

The routes match the shared frontend auth package (`BFFClient`):

| Route | Response |
|-------|----------|
| `GET /bff/session` | `200 {"authenticated": false}` or `{"authenticated": true, "user_id", "expires_at", "user": User, "apps"}` (`apps` only when `BFFConfig.Apps` is set) |
| `GET /bff/api/v1/users/me` | `200 User` or `401 {"code": "UNAUTHENTICATED", "message"}` |
| `GET /bff/auth/login?return_to=` | `302` to SystemAuth `/oauth/authorize` |
| `GET /bff/auth/{github,google}?return_to=` | Same, with `idp_hint` so SystemAuth skips its provider chooser |
| `GET /bff/auth/callback` | Verifies the login, creates the session, `302` to `return_to` |
| `POST /bff/auth/logout` | Deletes the session, revokes the SystemAuth refresh token, `204` |
| `POST /bff/auth/login` | `501 PASSWORD_LOGIN_UNSUPPORTED` (password login is not offered) |

`User` is `{id, email, name, avatar_url?, memberships: [{id, organization_id,
organization_name, organization_slug, role, joined_at}], created_at,
updated_at?}`. Errors are `{code, message}`.

A failed sign-in at `GET /bff/auth/login`, `/bff/auth/{provider}` or the
callback answers JSON by default. Set `BFFConfig.LoginErrorPath` (or
`appauth.Options.LoginErrorPath`) to the app's sign-in page, such as `/login`,
and the browser is redirected there with `?error=<CODE>` instead (`303`). The
codes are `LOGIN_FAILED`, `INVALID_STATE`, `EMAIL_NOT_VERIFIED`,
`ACCOUNT_CONFLICT`, `ACCOUNT_DISABLED`, `INVALID_RETURN_TO`, `UNKNOWN_PROVIDER`
and `INTERNAL_ERROR`; the upstream's error text is never copied into the URL.
A request with `Accept: application/json` (and not `text/html`) still gets
JSON. The path must pass the same checks as a `return_to`.

Security properties:

- The session cookie (`__Host-sf_rp_session`) is an opaque 256-bit token,
  `Secure`, `HttpOnly`, `SameSite=Lax`, host-only; only its SHA-256 hash is
  stored. SystemAuth tokens never reach the browser. A new token is issued on
  every login and any presented session is deleted (no fixation).
- Login state is single-use, server-side, and bound to the browser with a
  `__Host-sf_rp_state` cookie; PKCE and the OIDC `nonce` are always used.
- `InsecureCookies` drops `Secure` and the `__Host-` prefix for local
  development over plain HTTP; `NewBFF` logs a warning when it is set. See
  [Browser Cookies](../guides/cookies.md).
- The ID token is verified per OIDC Core §3.1.3.7 (RS256 signature against
  the JWKS, `iss`, `aud`/`azp`, `exp`, `nonce`), and the UserInfo `sub` must
  match it.
- `return_to` must be a same-origin path or an absolute URL on the app origin
  or `AllowedOrigins`.
- `POST /bff/auth/logout` and unsafe methods behind `RequireSession` require
  an allowed `Origin`, which browsers send on such requests; any body is then
  accepted, so file uploads work. A request without an `Origin` must have a
  JSON body, and an allowed `Referer` when it sends one.

`BFF.AccessToken(r)` returns a SystemAuth access token for the session,
refreshing it when it is about to expire and storing the rotated refresh
token; a rejected refresh (revoked, reused, or past
`refresh_token_absolute_lifetime`) ends the session.

Logging out of the app does not end the SystemAuth login session. To sign the
user out everywhere, send the browser to SystemAuth `GET /logout?return_to=...`
after `POST /bff/auth/logout`.

## Account linking

`ResolvePrincipal` applies the same rules as SystemAuth:

1. The `sub` (SystemAuth principal ID), stored as `sf_principal_id`, is the
   primary key: a linked principal signs in even if its email changed.
2. Otherwise a **verified** identity email links to an existing principal whose
   own email is verified and that is not linked to another SystemAuth
   principal.
3. Otherwise a principal is created, which requires a verified email.

An unverified email never links to or creates a principal; an email held by an
unverified (or differently linked) local principal is a conflict (`409
ACCOUNT_CONFLICT`).

## Memberships

Organization memberships (in `/bff/session`, `/bff/api/v1/users/me` and
`AuthenticatedPrincipal.Memberships`) come from a `MembershipSource`, which
receives the principal, its SystemAuth subject, and the verified SystemAuth
claims of the request (the ID token + UserInfo claims stored with the BFF
session, or the JWT access token's claims). SystemAuth is the source of
truth for memberships, application roles and entitlements (ADR-007), so
relying parties do not keep tables of their own. The sources:

| Source | Reads | Use |
|---|---|---|
| `ClaimsMemberships` (default) | The `orgs` claim: organization `id`, `role` and `apps` (application identifier to role); the ID token and userinfo form also has `slug`, `name` and `type`. Needs no network call | Production |
| `RemoteMemberships(client)` | `GET /oauth/userinfo/memberships`, all pages, with the request's access token | Production, when the claims cannot answer |
| `ClaimsOrRemoteMemberships(remote, logger)` | Claims, then the endpoint when `orgs_truncated` is set or the claim is absent; if the endpoint fails it serves the claims | Production, for users in more than 50 organizations |
| `LocalMemberships(lister)` | An app-local table (`MemoryPrincipalStore` implements `MembershipLister`) | Development and tests only; it diverges from SystemAuth |

```go
bff, err := relyingparty.NewBFF(relyingparty.BFFConfig{
    Client:      client,
    Principals:  principals,
    Memberships: relyingparty.ClaimsOrRemoteMemberships(relyingparty.RemoteMemberships(client), logger),
})
```

When `Memberships` is unset, `ClaimsMemberships` is used. A request without
claims then has no memberships; an application whose principals sign in by
other means supplies a source for them.
`Membership.Applications` carries the principal's role in each application;
an application absent from it is one the principal may not open.

An application with organization slugs in its URLs resolves one to its
organization ID with `client.ResolveOrganization(ctx, accessToken, slug)`,
which also follows a renamed organization's old slug during its cooling-off
period and reports it as an alias; see
[Resolving slugs in a relying party](../guides/organization-slugs.md#resolving-slugs-in-a-relying-party).

An application provisions itself for an organization on first use, keyed by
the SystemAuth organization ID, with `ProvisioningMemberships(source,
application, hook)`: the hook runs once per organization per process for a
principal who holds a role in `application` and must be idempotent.

## Access changes

Claims in a JWT access token are fixed when it is issued, so removing a
person from an organization does not reach a token already issued until it
expires. SystemAuth records each access change (ADR-010) and a
`RevocationCache` remembers the recent ones:

```go
cache := relyingparty.NewRevocationCache() // margin 30 s (floor 15 s), covers 15 min tokens

// In a modular monolith, hand the same cache to SystemAuth's services:
orgs := organization.NewService(db, organization.WithAccessChangeSink(accesschange.ToSink(cache)))

mw := relyingparty.BearerMiddleware(relyingparty.BearerConfig{
    Tokens: client, Principals: principals,
    DPoP:         &relyingparty.DPoPConfig{ReplayCache: replayCache, BaseURL: "https://api.example.com"},
    Revocation:   cache,
    Organization: func(r *http.Request) string { return r.PathValue("org") }, // optional
})
bff, _ := relyingparty.NewBFF(relyingparty.BFFConfig{Client: client, Principals: principals, Revocation: cache})
```

A JWT is accepted only if its `iat` is at or after the change plus the
clock-skew margin (`WithSkewMargin`, default 30 s, never below 15 s); a token
stamped inside the margin counts as issued before the change. Otherwise the
middleware answers `401` with `WWW-Authenticate: Bearer error="invalid_token",
error_description="token expired"`, which makes an OIDC client refresh and
obtain claims that reflect the change. When the request names an
organization, a change scoped to another organization does not refuse it;
without one, any change to the principal does. A token with no `iat` is
accepted only for a principal with no recorded change. Entries are dropped
once the change plus the maximum token lifetime (`WithMaxTokenLifetime`,
default 15 minutes) plus the margin has passed, so the cache holds only the
changes of the last token lifetime.

A BFF session does not end on a change. The BFF refreshes the session's
tokens, re-reads the claims from the userinfo endpoint, and keeps the person
signed in with reduced claims; a refresh SystemAuth refuses (deactivation,
revoked sessions) ends the session. The session is then stamped valid from
the latest change plus the margin, so one change causes one refresh. Session
stores persist this stamp (`Session.ClaimsIssuedAt`); `pgstore` keeps it in
the sealed secrets document.

### Replicas and restarts

Replicas of a monolith share the database, not memory. Each one polls
`sf_access_changes` once every second or two, independent of request volume,
and a restarted relying party replays the last token lifetime before it
trusts its cache:

```go
// Replicas sharing SystemAuth's database (PostgreSQL):
cache := relyingparty.NewRevocationCache(relyingparty.WithSuspectStart())
poller := relyingparty.NewAccessChangePoller(pgstore.NewAccessChangeSource(db), cache)
go poller.Run(ctx) // the first successful poll also ends suspect mode

// A relying party in another process, replaying through SystemAuth:
src := client.AccessChangesSource(client.ClientCredentialsToken(id, secret))
go relyingparty.ReplayWithRetry(ctx, src, cache, logger)
```

`WithSuspectStart` (or `MarkSuspect`) puts the cache in suspect mode: changes
made while it was not listening are unknown, so only tokens issued at least
one margin after it started are accepted, and the rest are answered "token
expired" so clients refresh. A successful `Replay`, or the first successful
poll, rebuilds the cache and ends suspect mode; a failure leaves it suspect,
so a restart never widens the window in which a revoked token is honored.
Replay retries with backoff and the server may start serving at once.

The poller re-reads from one margin behind its newest change, so a row that
committed late with an earlier timestamp is still seen. Its interval is
limited to 1 to 2 seconds. `accesschange.NewSource(entClient)` reads the same
table through Ent.

SystemAuth serves `GET /access-changes?since=<RFC 3339>[&limit=]` when built
with `systemauth.WithAccessChanges(accesschange.NewSource(db), scope)`. The
scope (`systemauth.AccessChangeScope`) limits each client to its
organizations' changes; `systemauth.AllOrganizations` serves the whole feed,
for a deployment of one application. The caller
needs a token with the `access_changes:read` scope, for example from the
client-credentials grant for a client registered with that scope. The
response is `{"changes": [{"principal_id", "organization_id", "changed_at",
"reason"}], "next_since": ...}`; `next_since` appears when more follow, and
the source follows it.

### Back-channel events

A relying party in another process can be told at once instead of polling.
Register an endpoint as the client's `backchannel_logout_uri` (an `https` URL,
or `http` for a loopback host; `ClientConfig.BackchannelLogoutURI`, stored on
`sf_oauth_apps`) and run SystemAuth's sender, passing it to the services that
record changes:

```go
bc := auth.NewBackchannel()
orgs := organization.NewService(db, organization.WithAccessChangeSink(bc))
go bc.Run(ctx)
```

For each change SystemAuth POSTs `logout_token=<jwt>` to every registered
client: an OpenID Connect Back-Channel Logout token (`typ` `logout+jwt`, signed
with the issuer key) with `sub`, `aud` (the client ID), `jti`, `iat`, `exp`
and an `events` claim. The `urn:systemforge:event:access_change` event carries
`organization_id` (absent for every organization), `changed_at` and `reason`;
for deactivation and session revocation the standard
`http://schemas.openid.net/event/backchannel-logout` event is added too.
Delivery is queued, retried with exponential backoff until one maximum
access-token lifetime after the change, and each failure is logged against the
client ID; a `4xx` other than 408 and 429 is not retried, and redirects are
never followed. With an access change scope, a client receives only its
organizations' changes and the changes that name no organization; without
one, every registered client receives every change. The token holds only
opaque identifiers.

The receiver is `relyingparty.BackchannelHandler(cache, client,
relyingparty.WithBackchannelSessions(store))`: it verifies the token against
the issuer's keys (`Client.VerifyLogoutToken`: signature, issuer, audience,
`typ`, `jti`, expiry, no `nonce`, a known event), records the access change
into the cache, and on a logout event deletes the sessions of the `sid`, or of
the `sub` when there is none. A repeated `jti` is refused, and a failure to end
sessions answers `500` so SystemAuth retries. The BFF already serves it at
`<BasePath>/auth/backchannel-logout` (`BFF.BackchannelLogoutHandler()` mounts
it elsewhere), ending its own sessions and feeding `BFFConfig.Revocation`.

## Sessions and back-channel logout

Each session records the SystemAuth `sub` and, when the ID token carries one,
the SystemAuth session ID (`sid`). `SessionStore.DeleteBySubject` and
`DeleteBySID` remove all matching sessions, which is what a back-channel
logout receiver needs.

## Implementing `PrincipalStore`

The package is storage-agnostic. An application with its own Ent schema
implements `PrincipalStore` over it; a principal entity using
`identity/ent/mixin.PrincipalMixin` already has the unique, indexed
`sf_principal_id` field:

```go
type entPrincipals struct{ db *ent.Client }

func (s entPrincipals) FindBySubject(ctx context.Context, sub string) (*relyingparty.Principal, error) {
    id, err := uuid.Parse(sub)
    if err != nil {
        return nil, relyingparty.ErrPrincipalNotFound
    }
    p, err := s.db.Principal.Query().Where(principal.SfPrincipalIDEQ(id)).Only(ctx)
    if ent.IsNotFound(err) {
        return nil, relyingparty.ErrPrincipalNotFound
    }
    if err != nil {
        return nil, err
    }
    return toRP(p), nil
}

// LinkSubject: UPDATE ... SET sf_principal_id = ? WHERE id = ?; map the unique
// violation to relyingparty.ErrSubjectLinked. CreatePrincipal: insert with
// sf_principal_id and a verified email; map unique violations to
// ErrSubjectLinked / ErrEmailConflict.
```

`MemoryPrincipalStore` is provided for development and tests.

## Programmatic clients

`BearerMiddleware` accepts, in order:

- `Authorization: DPoP <JWT>` with a `DPoP` proof header — a SystemAuth JWT
  access token bound to a DPoP key (`cnf.jkt`) and a proof signed by that key
  for this request (see [DPoP Enforcement](../session/dpop.md)). SystemAuth
  binds every token it issues, so `DPoP` is required whenever `Tokens` is set;
  the token is then checked as below.
- `Authorization: Bearer <JWT>`, only with `AllowBearerTokens` — an unbound
  SystemAuth JWT access token (a legacy client's), verified
  against the JWKS (`iss`, `exp`, a `typ` of `at+jwt` or `JWT`, and
  `Config.AccessTokenAudience` when set). The token must have been issued to
  an accepted client (see below); ID tokens are refused. Its `sub` must
  already be linked to a local principal (the user signed in to the app
  once). Client-credentials tokens (`sub` = `client_id`) are accepted as a
  `client` principal only with `AllowClientTokens`.
- The BFF session cookie, when `Sessions` is set.

Static API keys are not accepted: an opaque `Bearer` value is an invalid
token and `X-API-Key` is ignored. Command-line tools sign people in with
`identity/publicclient`, and automation uses service accounts (see
[Upgrading: Static API Keys Removed](../guides/app-authentication.md#upgrading-static-api-keys-removed)).

A DPoP-bound access token presented as `Bearer` is always refused, so a
stolen bound token cannot be replayed as a bearer token.

Failures return `401` with a `DPoP` challenge (carrying the error of a
failed DPoP request) and `WWW-Authenticate: Bearer realm="api"` (plus
`error="invalid_token"` for bad bearer credentials).

The `Client` itself proves possession of `Config.DPoPKey` in every token
request, so the tokens it obtains for the BFF are bound to that key, and it
presents them to SystemAuth with the DPoP scheme. Several instances that
share sessions must share the key (`dpop.DeserializeKeyPairJSON` from a
secret); otherwise a refresh on another instance is refused.

### Which clients' tokens are accepted

Every app that uses SystemAuth receives tokens signed with the same key, so
the verifier checks which client a token was issued to (its `client_id`
claim):

| Configuration | Accepted access tokens |
|---------------|------------------------|
| Default | Issued to this app's `ClientID` only |
| `AcceptedClientIDs` | Issued to one of the listed clients (list `ClientID` too to keep the app's own) |
| `AccessTokenAudience` | Carrying that `aud`, from any client; combine with `AcceptedClientIDs` to restrict clients too |

A service client that calls the API with client-credentials tokens must be
listed in `AcceptedClientIDs`:

```go
client, err := relyingparty.NewClient(ctx, relyingparty.Config{
    Issuer:            "https://auth.example.com",
    ClientID:          "my-app",
    RedirectURL:       "https://app.example.com/bff/auth/callback",
    AcceptedClientIDs: []string{"my-app", "reporting-service"},
})
```

## Managed principals

A relying party can create and manage managed principals, people without an
email whose accounts are controlled by managers, without holding SystemAuth's
database. SystemAuth serves the manager API at `/managed-principals` when
managed principals are enabled, and the application calls it with the
signed-in manager's access token through `managedprincipal/mpclient`:

```go
import "github.com/plexusone/systemforge/identity/managedprincipal/mpclient"

// rp.Transport presents the manager's DPoP-bound token with a proof.
mp := mpclient.New(issuer+"/managed-principals", &http.Client{Transport: rp.Transport(nil)})
learnerID, err := mp.Create(ctx, managerToken, mpclient.CreateInput{
    DisplayName: "Robin",
    Role:        "educator",
})
```

The client must have `managed_principals: true` and the
`systemforge:managed_principals` scope, and the manager's token must be
granted it. The client is taken from the token, the caller is the only
initial manager, and further managers join by invitation or claim. See
[Managed Principals](../identity/managed-principals.md#relying-parties-the-api-on-systemauth)
for the routes, their permissions, and configuration.

## Limitations

- JWT access tokens are verified statelessly: a revoked token stays usable
  until it expires (default 10 minutes, at most 15) unless the application configures a `RevocationCache` (see [Access changes](#access-changes)). Opaque SystemAuth access tokens are
  not accepted by `BearerMiddleware` (no introspection client yet).
- The default session and login-state stores are in-memory; use
  `relyingparty/pgstore` (encrypted at rest) or another shared implementation
  in production. See [Production Stores](production-stores.md).
- Back-channel notifications are sent only to clients that register a
  `backchannel_logout_uri`; there is no front-channel logout.
