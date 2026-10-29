# Production Checklist

Walk this list before an application that embeds SystemAuth, or runs the
`systemauth` server, takes real traffic. Each item is one decision or one
setting; the links lead to the full reference. Re-walk it after an upgrade
that adds a production check, and after any change to the edge or the
number of instances.

The checklist puts the operator-side assumptions of the
[threat model](threat-model.md) into practice; read its residual risks
before deciding which waivers to accept.

## Keys and secrets

- [ ] **The signing key comes from a secret store.** Load it through
  `SYSTEMAUTH_SIGNING_KEY` or a file the secret store writes, never a
  command-line flag or a key committed with the config
  ([Signing key](../systemauth/deployment.md#signing-key)).
- [ ] **A signing-key rotation drill has been done.** Keep the current and
  the previous key valid; retire the older one only after the new one is
  verified everywhere ([Rotating Keys and Secrets](../guides/rotation.md#the-rule)).
- [ ] **`tokens.hmac_secret` is set, and identical on every instance.**
  Without it refresh tokens and authorization codes stop working at a
  restart and on other instances
  ([Token HMAC secret](../systemauth/deployment.md#token-hmac-secret)).
- [ ] **Relying parties keep their DPoP key pairs as secrets.** One key per
  session, stored with the same care as its refresh token and shared by
  every replica that shares the session
  ([Calling APIs with DPoP](../guides/dpop-clients.md#keep-one-key-pair)).
- [ ] **BFF session sealing keys come from a key ring, with a rotation
  plan.** ([BFF Sessions](../session/bff-sessions.md#rotating-keyring-keys),
  [Rotating Keys and Secrets](../guides/rotation.md#bff-session-sealing-keys)).
- [ ] **The connection-credential root key is not stored beside the key
  ring.** Keep it in the secret store, with a second copy kept apart from
  the keys directory and its backups
  ([Key Management](../guides/key-management.md#set-it-up)).

## Production checks

- [ ] **The server starts without dev mode.** `--dev` replaces the signing
  key, storage and issuer with development values
  ([Production requirements](../systemauth/deployment.md#production-requirements)).
- [ ] **The fail-closed checks pass without waivers, or each waiver is
  deliberate.** Outside dev mode, startup refuses:

    - a missing `tokens.hmac_secret` (waiver: `ephemeral_hmac_secret`);
    - a static client with `allow_bearer_tokens` (waiver:
      `bearer_token_clients`);
    - a per-instance DPoP replay cache, unless `dpop.replay_cache_redis_url`
      is set or `dpop.single_instance: true` declares one instance;
    - `mail.provider: log`, which writes verification links to the log (no
      waiver; see [Verified Email](../systemauth/verified-email.md)).

    The token endpoint also refuses, with `unauthorized_client`, the
    `client_credentials` grant from a client using a shared secret (waiver:
    `client_secret_client_credentials`) and every request from a client
    registered with `allow_bearer_tokens`. Waivers are names listed under
    `production.allow`.
- [ ] **Every waiver logged at startup has been reviewed.** Each one is
  logged when the server starts; read the startup log of a production
  instance and confirm each waiver is still intended.
- [ ] **`systemauth validate` passes on the production configuration.**
  ([Flags and environment](../systemauth/deployment.md#flags-and-environment)).

## Shared stores

- [ ] **More than one instance means shared stores.** Per-instance (in-memory)
  stores are acceptable only when exactly one instance runs
  ([Production Stores](../systemauth/production-stores.md)).
- [ ] **The DPoP replay cache is shared by every instance.** An in-memory
  cache lets a proof replayed against another instance through
  ([DPoP Enforcement](../session/dpop.md#systemauth-issues-dpop-bound-tokens)).
- [ ] **Rate-limit counters are shared by every instance.** In-memory
  counters multiply the effective limit by the number of instances: set
  `rate_limit.redis_url`, or declare one instance with
  `rate_limit.single_instance`
  ([Rate limits](../systemauth/deployment.md#rate-limits)).

## Edge and origin

- [ ] **TLS terminates at the CDN or reverse proxy, and the issuer is
  https.** Terminating at the edge is fine.
- [ ] **The origin accepts traffic only from the proxy.** Firewall the origin
  to the proxy's address ranges, or require authenticated origin pulls.
- [ ] **TLS between edge and origin is full and strict.** The edge verifies
  the origin's certificate; no plain-HTTP hop.
- [ ] **HSTS is sent** on every https response.
- [ ] **Trusted proxy networks are configured.** Client addresses come from
  the header your proxy sets (for example `CF-Connecting-IP`, or
  `X-Forwarded-For` written by your own proxy), and only when the request
  comes from a trusted proxy network, never from the open internet. Set
  `client_address` in SystemAuth and share the same `clientaddr.Resolver`
  with the BFF, `appauth` and the application's rate limits
  ([Client Addresses and Rate Limiting](../guides/rate-limiting.md#the-client-address)).
- [ ] **The reverse proxy replaces `X-Forwarded-For`** with the one client
  address it trusts, rather than appending to a value the client sent.
- [ ] **The DPoP base URL matches the external URL** when the proxy rewrites
  paths ([The proof's URL behind a proxy](../session/dpop.md#the-proofs-url-behind-a-proxy)).
- [ ] **In-app rate limits are on, with the route policies reviewed.** The
  default per-address limit covers every route; the token, login and sign-up
  paths have their own lower limits, and back-channel callers that share an
  address are in `rate_limit.exempt_networks`
  ([Rate limits](../systemauth/deployment.md#rate-limits)). An edge
  rate-limit rule is optional extra protection against floods that should
  not reach the origin at all.
- [ ] **WAF managed rules are on.**
- [ ] **The payment-provider webhook path is exempt from WAF and bot
  challenges.** A challenge there makes the provider's deliveries fail.

## Logging

- [ ] **Logs are JSON in production** ([Flags and environment](../systemauth/deployment.md#flags-and-environment)).
  SystemAuth logs OAuth errors as a code-and-hint summary in either format;
  the host application's own error values may still print stack traces in
  the text format.
- [ ] **Security events are recorded** through `Options.AuditEmitter`, to an
  audit store or the log, and someone watches the refusal and replay events
  ([Security Events](security-events.md)).
- [ ] **No tokens, secrets or authorization headers reach the logs**,
  including from the host application, proxies and request logging.
- [ ] **Logs are shipped off the host** to a collector with retention and
  access control.

## Database

- [ ] **The application and migrations use separate database logins.** The
  application login cannot change the schema or bypass row-level security.
- [ ] **Row-level security is enabled** on tenant tables, with the `rls`
  package setting the tenant for each transaction.
- [ ] **Backups run, and a restore has been tested** into a separate
  environment.

## Billing

- [ ] **The webhook signing secret is set, per environment.** Each
  environment has its own endpoint and secret.
- [ ] **Live keys are used only in production**, and test keys everywhere
  else.
- [ ] **Checkout and portal redirects are limited to an allowlist of your
  own hosts.**
- [ ] **The webhook endpoint is subscribed to the events the application
  needs**, and to no others.

## Monitoring and response

- [ ] **Alerts fire on sign-in failures, 429s and 5xx responses**
  ([Observability](../observability/overview.md)).
- [ ] **Someone is on call**, and knows where the runbooks below are.
- [ ] **The team knows how to revoke a client**
  ([Deactivating Apps](../oauth/apps.md#deactivating-apps),
  [Token Revocation](../oauth/tokens.md#token-revocation)).
- [ ] **The team knows how to rotate every key and secret**
  ([Rotating Keys and Secrets](../guides/rotation.md)).
- [ ] **The team knows how to invalidate all sessions**
  ([Session Invalidation](../session/invalidation.md),
  [Access-Change Invalidation](../guides/access-change-invalidation.md)).

## Branch protection and CI

- [ ] **The default branch is protected**, with pull requests required.
- [ ] **Required checks cover tests, lint, CodeQL and the Postgres
  integration tests.**
- [ ] **`govulncheck` runs in CI** and on a schedule, so a newly published
  advisory against a dependency, or against SystemForge, is reported.
