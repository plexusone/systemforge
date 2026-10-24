# Access-change invalidation

Access tokens are self-contained JWTs, so removing a person from an
organization or lowering a role does not reach a token already issued.
SystemForge bounds that window two ways: short token lifetimes, and a record
of every access-reducing change that relying parties consult. The design is
in [Organizations and Membership](../design/architecture/organizations.md#token-freshness-and-revocation);
the relying-party API is in [Relying Parties](../systemauth/relying-party.md#access-changes).

## Token lifetime

| Setting | Default | Limit |
|---|---|---|
| `tokens.access_token_lifetime` | 10 minutes | 15 minutes; a larger value fails configuration loading with `ErrInvalidConfig` |
| Per client `access_token_lifetime` (and `sf_oauth_apps.access_token_ttl`) | The server value | Capped at 15 minutes |
| `tokens.refresh_token_lifetime` | 7 days (absolute 30 days) | |

A membership or role change does not revoke refresh tokens: the next refresh
re-evaluates the `orgs` claim and issues reduced claims. Only deactivation
and explicit session revocation revoke refresh tokens.

## What is recorded

`sf_access_changes` receives a row, in the transaction that makes the
change, for: `membership_removed`, `org_role_changed`, `app_role_changed`,
`deactivated`, `sessions_revoked`, `management_granted`, `management_ended`
and `grant_reduced`. Adding access records nothing. Pass a sink to each
service with `WithAccessChangeSink`; rows are written with or without one.
`accesschange.PruneExpired` deletes rows past `accesschange.Retention`; call it
from your own maintenance loop.

## Relying-party revocation cache

A token is accepted only if its `iat` is at or after the recorded change plus
a clock-skew margin (30 seconds by default, never below 15).

```go
cache := relyingparty.NewRevocationCache()
mw := relyingparty.BearerMiddleware(relyingparty.BearerConfig{
    Tokens: client, Principals: principals, Revocation: cache,
})
```

| Deployment | Feed the cache with |
|---|---|
| Modular monolith, one process | `accesschange.ToSink(cache)` passed to every service's `WithAccessChangeSink` |
| Replicas sharing the database | `relyingparty.NewAccessChangePoller(source, cache).Run(ctx)`, polling every 1 to 2 seconds, with `WithSuspectStart()` on the cache |
| Another process | `relyingparty.ReplayWithRetry` against `GET /access-changes?since=`, plus back-channel delivery |
| Separate deployments | Back-channel events (below) |

After a restart a cache created with `WithSuspectStart` refuses tokens
issued before it started until the first replay or poll succeeds, so a
restart never widens the window.

## Replay endpoint

Enable `GET /access-changes?since=<RFC 3339>[&limit=]` with
`systemauth.WithAccessChanges(accesschange.NewSource(db), scope)`. The caller
needs a client-credentials token with the `access_changes:read` scope. The
response is `{"changes": [...], "next_since": ...}`; a page filtered by the
scope may be short or empty and still carry `next_since`.

The second argument, a `systemauth.AccessChangeScope`, limits each client to
the organizations whose changes it may read; changes that name no
organization (a deactivation, revoked sessions) reach every client. It is
called with the token's client ID and returns organization IDs, or `all` for
a client that may read everything. In a deployment of several applications,
return the organizations that use the client's application, so one
application does not learn about another's members.
`systemauth.AllOrganizations` gives every client the whole feed, for a
deployment of one application. Without a scope the endpoint answers `501`.
The same scope filters back-channel deliveries.

| Status | Cause |
|---|---|
| `401` | Missing or invalid token |
| `403` | The token lacks `access_changes:read` |
| `400` | `since` is not RFC 3339, or `limit` is not a positive integer |
| `501` | Access changes, or their scope, are not configured |

## Back-channel delivery

Register the client's endpoint (an `https` URL, or `http` for a loopback
host) as `backchannel_logout_uri` (`ClientConfig.BackchannelLogoutURI`,
column `sf_oauth_apps.backchannel_logout_uri`, migration
`0007_oauth_app_backchannel_logout_uri.sql`) and run SystemAuth's sender:

```go
bc := auth.NewBackchannel()
orgs := organization.NewService(db, organization.WithAccessChangeSink(bc))
go bc.Run(ctx)
```

SystemAuth POSTs an OpenID Connect Back-Channel Logout token carrying the
`urn:systemforge:event:access_change` event to every registered client
(within the access change scope, when one is configured),
retrying with backoff for up to one maximum token lifetime and never
following redirects; a `4xx` other than 408 and 429 is not retried. The
receiver is `relyingparty.BackchannelHandler(cache, client, ...)`; the BFF
serves it at `<BasePath>/auth/backchannel-logout`.

## What a client sees

| Situation | Response |
|---|---|
| Token issued before a recorded change | `401` with `WWW-Authenticate: Bearer error="invalid_token", error_description="token expired"`; refresh and retry |
| BFF session after a change | The session refreshes its tokens and claims and stays signed in with reduced claims |
| Refresh refused (deactivation, revoked sessions) | The session ends |
| Back-channel token invalid (signature, issuer, audience, `typ`, `jti` replay) | The receiver refuses it; a failure to end sessions answers `500` so SystemAuth retries |

Applications that bypass `relyingparty` must implement the same check.
