# Production Checklist

Walk this list before an application that embeds SystemAuth, or runs the
`systemauth` server, takes real traffic. Each item is one decision or one
setting; the links lead to the full reference. Re-walk it after an upgrade
that adds a production check, and after any change to the edge or the
number of instances.

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

<!-- TODO(RMI-SYSTEMFORGE-203): exact keys -->

- [ ] **The server starts without dev mode.** `--dev` replaces the signing
  key, storage and issuer with development values
  ([Production requirements](../systemauth/deployment.md#production-requirements)).
- [ ] **The fail-closed checks pass without opt-outs, or each opt-out is
  deliberate.** From v0.27.0, startup refuses, unless explicitly opted out:

    - a missing token HMAC secret;
    - the client-credentials grant with a shared client secret;
    - clients exempt from DPoP;
    - a per-instance replay cache, unless a shared (Redis) replay cache or
      an explicit single-instance setting is configured.
- [ ] **Every opt-out logged at startup has been reviewed.** Each one is
  logged when the server starts; read the startup log of a production
  instance and confirm each opt-out is still intended.
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
  counters multiply the effective limit by the number of instances
  ([Rate Limiting](../coreapi/ratelimit.md#redis-storage)).

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
  comes from a trusted proxy network, never from the open internet
  ([ClientIPConfig](../bff/overview.md#clientipconfig-cloudflare-support)).
- [ ] **The DPoP base URL matches the external URL** when the proxy rewrites
  paths ([The proof's URL behind a proxy](../session/dpop.md#the-proofs-url-behind-a-proxy)).
- [ ] **An edge rate-limit rule covers the token, login and sign-up paths.**
  Keep it until in-app layered limits ship.
- [ ] **WAF managed rules are on.**
- [ ] **The payment-provider webhook path is exempt from WAF and bot
  challenges.** A challenge there makes the provider's deliveries fail.

## Logging

- [ ] **Logs are JSON in production.** The text format prints error stack
  traces ([Flags and environment](../systemauth/deployment.md#flags-and-environment)).
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
