# Deploying SystemAuth

The `cmd/systemauth` binary is a self-contained SystemAuth server suitable for
running under a process supervisor (systemd) behind a TLS-terminating reverse
proxy (Caddy, nginx). To run SystemAuth inside another Go binary instead, see
[Embedding](embedding.md).

## Production requirements

Unless started with `--dev`, the server refuses to start without:

- a **signing key** (`keys.private_key_file`, `keys.private_key_pem`,
  `--signing-key-file`, or the `SYSTEMAUTH_SIGNING_KEY` environment variable),
- a public **https issuer** (cookies are `Secure`/`__Host-`, and the issuer is
  what relying parties verify tokens against),
- a persistent **database** (PostgreSQL or SQLite),
- a [**token HMAC secret**](#token-hmac-secret) (`tokens.hmac_secret`),
- a DPoP **replay cache** every instance shares
  (`dpop.replay_cache_redis_url`), or `dpop.single_instance: true` when one
  instance serves SystemAuth (see [DPoP](#dpop)),

and it rejects `social_login.insecure_cookies` and statically configured
clients that set `allow_bearer_tokens`. `--dev` relaxes all of these
(ephemeral key, in-memory storage, `http://localhost` issuer).

It also warns, without refusing, when the [rate limit](#rate-limits)
counters are kept in memory and neither `rate_limit.single_instance` nor
`dpop.single_instance` declares one instance.

Outside `--dev` the token endpoint also refuses, per request, so that
clients registered at runtime are covered:

- the `client_credentials` grant from a client that authenticates with a
  shared client secret, with `unauthorized_client`. Use
  [service accounts](../oauth/service-accounts.md) with the JWT-bearer grant
  instead. Confidential clients keep using their secret for the
  `authorization_code` and `refresh_token` grants, and discovery no longer
  lists `client_credentials`;
- every request from a client registered with `allow_bearer_tokens`, with
  `unauthorized_client`, so no token is issued without a DPoP binding.

### Waiving a production check

A deployment that must run without one of these checks names it in
`production.allow`; anything else there is a configuration error. Each
waiver is logged as a warning at every start:

```yaml
production:
  allow:
    - ephemeral_hmac_secret             # start without tokens.hmac_secret
    - client_secret_client_credentials  # serve client_credentials with a shared secret
    - bearer_token_clients              # serve clients with allow_bearer_tokens
```

The replay cache has no waiver: `dpop.single_instance: true` is the
statement that one instance serves SystemAuth, and is also logged as a
warning.

With a database configured, social login sessions, in-flight upstream logins
and consent grants are stored in it (`sf_login_sessions`, `sf_login_states`,
`sf_consent_grants`). With a [token HMAC secret](#token-hmac-secret) as
well, restarts keep users signed in and several instances can run behind a
load balancer on one PostgreSQL database. Statically
configured clients are updated from the configuration on each start. See
[Production Stores](production-stores.md).

## Flags and environment

Running `systemauth` without a subcommand serves. Go-style single-dash flags
(`-addr`) are accepted, and every flag can be set from an environment variable
when it is not on the command line:

| Flag | Environment | Default | Notes |
|------|-------------|---------|-------|
| `--config`, `-c` | `SYSTEMAUTH_CONFIG` | — | YAML/JSON config; `${ENV}` references are expanded (see [Secrets](#secrets)) |
| `--addr` | `SYSTEMAUTH_ADDR` | `:8080` | e.g. `127.0.0.1:8081` behind a proxy (`--listen` is a deprecated alias) |
| `--issuer` | `SYSTEMAUTH_ISSUER` | config | Public URL, e.g. `https://auth.example.com` |
| `--signing-key-file` | `SYSTEMAUTH_SIGNING_KEY_FILE` | config | PEM RSA key (PKCS#1 or PKCS#8, ≥ 2048 bits) |
| — | `SYSTEMAUTH_SIGNING_KEY` | — | PEM key content (never a flag: command lines are visible to other users) |
| `--key-id` | `SYSTEMAUTH_KEY_ID` | key thumbprint | JWKS `kid` |
| `--db-driver`, `--db-dsn` | `SYSTEMAUTH_DB_DRIVER`, `SYSTEMAUTH_DB_DSN` | config | `postgres` (pgx) or `sqlite` |
| `--migrate` | `SYSTEMAUTH_MIGRATE` | `true` | Run schema migrations at startup |
| `--invite-only` | `SYSTEMAUTH_INVITE_ONLY` | `false` | Create accounts only for verified emails that hold a sign-up invite |
| `--signup-denied-url` | `SYSTEMAUTH_SIGNUP_DENIED_URL` | — | https page a refused sign-up is sent to, with `error=invite_required`; without it, SystemAuth's own waitlist page |
| `--dev` | `SYSTEMAUTH_DEV` | `false` | Development mode |
| `--log-level`, `--log-format` | `SYSTEMAUTH_LOG_LEVEL`, `SYSTEMAUTH_LOG_FORMAT` | `info`, `text` | Use `json` under a log collector |

`systemauth validate` checks a configuration, including the production
requirements; `systemauth migrate` runs migrations only.

## Secrets

`${NAME}` and `$NAME` references in the secret fields of the configuration
(client secrets, `keys.*`, `tokens.hmac_secret` and
`tokens.hmac_verification_secret`, `database.dsn`, `dpop.nonce_secret`,
`dpop.replay_cache_redis_url`, `rate_limit.redis_url`, social login and
federation credentials, and the SpiceDB token and URIs) are resolved by the
`secrets` package through an [omnivault](https://github.com/plexusone/omnivault)
vault. By default that vault is the process environment, and expansion works
exactly like `os.ExpandEnv`: a missing variable becomes the empty string. A
value that is entirely one `${NAME}` reference, such as
`private_key_pem: ${SYSTEMAUTH_SIGNING_KEY}`, is substituted without being
scanned again, so a `$` inside the secret is kept.

To read the references from another vault, name it in `secrets.vault`; each
`NAME` is then the secret's path in that vault:

```yaml
secrets:
  vault: file:///etc/systemauth/secrets   # or env://PREFIX_, or ${SECRETS_VAULT}
tokens:
  hmac_secret: ${systemauth/hmac}
```

The built-in schemes are `env://`, `file://` and `memory://`. SystemForge
imports no cloud SDK: to use a cloud secret manager, build your own binary
whose `main` package imports that omnivault provider's registration package
(which calls `omnivault.RegisterProvider` for its scheme), or pass a resolver
to `systemauthsvc.LoadConfigWithResolver` (or
`systemauth.LoadConfigWithResolver`):

```go
v, err := newCloudVault(ctx) // any omnivault.Vault, e.g. from a cloud provider package
if err != nil {
    return err
}
r, err := secrets.New(v)
if err != nil {
    return err
}
defer r.Close()
cfg, err := systemauthsvc.LoadConfigWithResolver(ctx, path, r)
```

A resolver passed this way takes precedence over `secrets.vault`. Errors
other than a missing secret, such as an unreachable vault or a denied read,
fail the load rather than leaving the field empty.

## Invite-only sign-up

Start with `--invite-only` to let new accounts in only by invitation, for
example while a deployment is being brought up. An email invite names an
address: the person signs in with the upstream provider, and an account is
created only when the provider's **verified** email holds a pending invite.
Invite codes, shared as links, are described in
[Invite-Gated Sign-Up](../guides/invite-gated-signup.md).
People who already have an account sign in as before, and an unverified
address never matches.

```bash
systemauth invite add ada@example.com grace@example.com --note "launch cohort" --expires-in 168h
systemauth invite list          # pending invites; --all includes redeemed ones
systemauth invite revoke ada@example.com
```

- **Redeeming:** the first account created with an address consumes its
  invite. Revoking a redeemed invite does not touch the account; it only
  allows the address to be invited again.
- **No reason is given on refusal.** A visitor cannot tell an address with no
  invite from one whose invite expired.
- **Waitlist.** A refused sign-up lands on `/signup/waitlist`, served by
  SystemAuth while invite-only is on: a notify-me form that records the
  address with the consent text shown and its version. It answers the same
  whether or not the address was already listed, accepts posts only from
  SystemAuth's own or an allowed origin, and is rate-limited per client
  address and per submitted address. Nothing is emailed; operators export
  the list:

  ```bash
  systemauth waitlist list          # oldest first; --csv to export
  systemauth waitlist remove ada@example.com
  ```

  A host binary sets the page's wording with `Options.WaitlistPage` and
  reads the list with `Service.SignupWaitlist()`. Behind a proxy, configure
  [`client_address`](#client-address) so the per-address limit sees real
  clients.
- **Database:** the commands read the configured database directly, so they
  work with the server running. The table is created by the schema migration.
- **In a host binary,** set `Options.InviteOnly` and `Options.SignupDeniedURL`
  on `systemauthsvc.New`, and manage invites with `Service.SignupInvites()`.
- **Invite codes, member invites and the invite API** build on invite-only
  sign-up: see [Invite-Gated Sign-Up](../guides/invite-gated-signup.md) for
  `Options.SignupCodes`, `MemberInvites`, `SignupAPI`, and the `code`,
  `allowance`, `waitlist invite` and `admin` commands.

## Minimum sign-up age

Set `social_login.signup_minimum_age` to ask a person their birth month and
year before their first upstream login creates an account:

```yaml
social_login:
  signup_minimum_age: 18
```

- **Nothing is kept before the answer.** The login is parked with only its
  provider and destination; the provider's email and profile are not stored.
  The person answers on `/signup/age`, served by SystemAuth.
- **At or over the age,** SystemAuth restarts the upstream login, which then
  creates the account. The provider usually returns at once without asking
  again.
- **Under the age,** the parked login is discarded, no account exists, and
  the browser is not asked again for a day. Only the refusal is logged, with
  the provider and no answer.
- **The question is neutral.** Month and year start empty, and the year list
  includes years too recent to pass, so it does not hint at the answer.
  Without the day, the last day of the birth month counts, so nobody younger
  passes.
- **Only new accounts are asked.** Existing accounts, and children signing in
  with login tokens, sign in as before. With invite-only sign-up, an
  uninvited login is refused before it is asked, and the invite is used only
  once the age is confirmed.
- **It is a stated age, screened at social sign-up only.** The refusal is
  remembered per browser, so a person who clears cookies can answer again.
  Accounts created through `signup.Service`, federation sync or SCIM are not
  asked; see [Minimum Sign-Up Age](../guides/signup-age.md#limits).
- **In a host binary,** set the wording with `Options.SignupAgePage`.

See [Minimum Sign-Up Age](../guides/signup-age.md) for what a person sees
and how the answer is decided.

## App catalog

A deployment that hosts several applications can publish their catalog for
the product switcher in each application's shell: name, launch URL, icon
and order, keyed by the same identifier as the application's vocabulary.
Pass `Options.Apps` (an `appcatalog.Catalog`) to `systemauthsvc.New`;
SystemAuth serves it at `/.well-known/sf-apps`. It is public, since names
and URLs are not secret.

A relying party lists it in its browser session (`"apps"` in the
`/bff/session` response) by setting `BFFConfig.Apps`: `appcatalog.Static`
when it runs in the same process, or `appcatalog.Remote(issuer, ...)`,
which fetches and caches the published catalog. A shell shows the entries
the person holds a role in for the current organization (the membership's
`applications`), so an application that is not registered or not entitled
never appears.

## Connections to external services

Setting `connections` in the configuration lets organizations connect
accounts at services such as a CDN or analytics product. It needs a database
and the role-based authorization mode, and it adds a keys directory that must
be backed up with the database:

```yaml
connections:
  keys_dir: /var/lib/systemauth/keys
  vault: env://
  root_key: SYSTEMAUTH_KEYS_ROOT   # 32 bytes, base64 or hex; keep a copy offline
```

`systemauth migrate` creates the `connectforge_*` tables and, on
PostgreSQL, enables row-level security on them. `systemauth serve` runs the
key lifecycle jobs. See [Connections](../guides/connections.md) and
[Key management](../guides/key-management.md).

## Signing key

Generate a key once and keep it in your secret store:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out systemauth-signing.pem
```

Provide it as a file readable only by the service user, or as PEM content in
`SYSTEMAUTH_SIGNING_KEY`. The JWKS `kid` defaults to the key's RFC 7638
thumbprint, so a new key gets a new `kid`.

### Rotating the signing key

SystemAuth keeps two keys: the current key N, which signs, and the previous
key N-1, which only verifies. `keys.verification_keys` lists the keys that
are published in the JWKS and accepted when verifying tokens without ever
signing. A token's `kid` selects its key; a token with any other `kid` is
refused. Rotate in two deploys, so that both a rollout and a rollback keep
every live token verifying:

1. **Pre-stage.** Generate key N and add it as a verification key while
   N-1 still signs. Relying parties see N in the JWKS before any token
   signed with it exists.

    ```yaml
    keys:
      private_key_file: /etc/systemauth/signing-2.pem   # N-1, signing
      key_id: signing-2
      verification_keys:
        - key_id: signing-3                               # N, pre-staged
          public_key_file: /etc/systemauth/signing-3.pem
    ```

2. **Promote.** Make N the signing key and move N-1 into
   `verification_keys`. Drop N-2 now, never N-1: tokens N-1 signed are in
   use until they expire. Rolling this deploy back to step 1 still verifies
   the tokens N signed meanwhile, because step 1 publishes N.

    ```yaml
    keys:
      private_key_file: /etc/systemauth/signing-3.pem   # N, signing
      key_id: signing-3
      verification_keys:
        - key_id: signing-2                               # N-1
          public_key_file: /etc/systemauth/signing-2.pem
    ```

A verification key may be a public key (`PUBLIC KEY` or `RSA PUBLIC KEY`
PEM) or the private key file, of which only the public part is used; give
it as `public_key_file` or `public_key_pem`. Its `key_id` defaults to the
key's thumbprint, which is also the default `kid` of a signing key. Keep N-1
until the longest-lived token it signed has expired: ID tokens (1 hour by
default) and JWT access tokens (at most 15 minutes); opaque tokens and
refresh tokens are not signed with it.

## Token HMAC secret

Authorization codes, refresh tokens and opaque access tokens are signed
with an HMAC secret, not the signing key. Set `tokens.hmac_secret` to at
least 32 bytes, the same on every instance, and keep it in your secret
store like the signing key:

```bash
openssl rand -hex 32
```

```yaml
tokens:
  hmac_secret: ${SYSTEMAUTH_TOKEN_HMAC_SECRET}
```

Outside `--dev` the server refuses to start without it, unless
`production.allow` names `ephemeral_hmac_secret`. SystemAuth then generates
a secret at each start and logs a warning. Every refresh token stops
working at the next restart, so a relying party cannot refresh and sends
its users through sign-in again after each deploy, and a second instance
refuses the first one's codes and refresh tokens.

### Rotating the HMAC secret

`tokens.hmac_verification_secret` is a second secret whose tokens are
accepted but never signed with. Rotate in two deploys, as for the signing
key:

1. **Pre-stage.** Keep N-1 as `hmac_secret` and set N as
   `hmac_verification_secret`.
2. **Promote.** Make N the `hmac_secret` and move N-1 to
   `hmac_verification_secret`. Rolling back to step 1 still accepts the
   tokens N signed.

Keep N-1 until `tokens.refresh_token_lifetime` (7 days by default) has
passed since the promotion: a refresh token signed with it and not used
since is refused once it is dropped, and its user signs in again.

## Example: systemd + Caddy

`/etc/systemauth/env` (mode `0600`):

```bash
SYSTEMAUTH_ARGS=-addr 127.0.0.1:8081 -config /etc/systemauth/config.yaml -log-format json
SYSTEMAUTH_SIGNING_KEY_FILE=/etc/systemauth/signing.pem
DATABASE_URL=postgres://systemauth:secret@127.0.0.1:5432/systemauth?sslmode=disable
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
```

`/etc/systemd/system/systemauth.service`:

```ini
[Unit]
Description=SystemAuth OAuth 2.0 / OpenID Connect server
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
EnvironmentFile=/etc/systemauth/env
ExecStart=/usr/local/bin/systemauth $SYSTEMAUTH_ARGS
User=systemauth
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict

[Install]
WantedBy=multi-user.target
```

systemd splits `$SYSTEMAUTH_ARGS` into words, so the flags can live in the
environment file. `/etc/systemauth/config.yaml`:

```yaml
issuer: https://auth.example.com
database:
  driver: postgres
  dsn: ${DATABASE_URL}
keys:
  private_key_file: ${SYSTEMAUTH_SIGNING_KEY_FILE}
tokens:
  hmac_secret: ${SYSTEMAUTH_TOKEN_HMAC_SECRET}
dpop:
  single_instance: true   # or replay_cache_redis_url with several instances
client_address:
  trusted_proxies: ["127.0.0.1/32", "::1/128"]   # Caddy on this host
rate_limit:
  single_instance: true   # or redis_url with several instances
features:
  require_pkce: true
  enable_jwt_access_tokens: true
social_login:
  github:
    client_id: ${GITHUB_CLIENT_ID}
    client_secret: ${GITHUB_CLIENT_SECRET}
  allowed_redirect_origins:
    - https://app.example.com
```

Caddy terminates TLS and proxies to the loopback listener, replacing
`X-Forwarded-For` with the client's address:

```
auth.example.com {
    reverse_proxy 127.0.0.1:8081 {
        header_up X-Forwarded-For {client_ip}
    }
}
```

Behind a CDN or edge proxy, give Caddy the edge's networks
(`trusted_proxies`) and the header it writes (`client_ip_headers`) in its
global `servers` options, so `{client_ip}` is the visitor rather than the
edge.

## Client address

SystemAuth finds a request's client address for its rate limits, the
addresses it records and audit events. It believes a forwarding header only
from the networks in `client_address.trusted_proxies`:

```yaml
client_address:
  trusted_proxies: ["127.0.0.1/32", "::1/128"]
  header: X-Forwarded-For   # the default; or a single-value header such as CF-Connecting-IP
```

`X-Forwarded-For` is read from the right, skipping trusted proxies; a
single-value header must hold exactly one address. Without
`client_address`, every request is attributed to its direct peer, which
behind a proxy is the proxy itself, so all clients would share one limit. See
[Client Addresses and Rate Limiting](../guides/rate-limiting.md).

## Rate limits

SystemAuth limits requests in layers, all on one storage:

- a **default** limit per client address on every route, before anything
  authenticates (300 a minute);
- **route policies** for `/oauth/token` (per address and per client),
  `/login*`, `/signup*` and `/bff/auth/*` (per address, lower), with health
  checks, static assets and the payment webhook exempt;
- a limit per **signed-in** principal or service account after
  authentication (1200 a minute), on the managed-principal API;
- **handler limits** that need the outcome: failed client authentication,
  JWT-bearer tokens per service account, social login start and callback,
  login-token exchange, the waitlist and the sign-up page.

Refusals are `429` with `Retry-After` (at least one second) and the
`RateLimit-Policy` and `RateLimit` headers. When the storage fails, the
default layer lets requests through and logs; the token, login and sign-up
limits refuse with `503`.

```yaml
rate_limit:
  redis_url: ${SYSTEMAUTH_RATE_LIMIT_REDIS_URL}   # shared by several instances
  # single_instance: true                        # or one instance, in memory
  default: {requests: 300, period: 1m}
  exempt_networks: ["10.20.0.0/16"]              # relying parties' servers
  routes:
    - name: token
      paths: ["/oauth/token"]
      per_address: {requests: 60, period: 1m}
      per_client: {requests: 600, period: 1m}
```

Counters in memory suit one instance. With several instances set
`rate_limit.redis_url` (or pass `Options.RateLimitStorage`): otherwise each
instance allows the full limit. Outside `--dev` the server warns at startup
when the counters are in memory and no single instance is declared
(`rate_limit.single_instance`, or `dpop.single_instance`, which declares the
same deployment). It warns rather than refuses because per-instance counters
loosen the limits without bypassing a check, unlike an unshared DPoP replay
cache. A relying party's server that calls the token endpoint for many users
from one address belongs in `exempt_networks`, or needs a higher `token`
limit. The full reference is in
[Client Addresses and Rate Limiting](../guides/rate-limiting.md).

## Security headers

Every SystemAuth response, including the login, consent, sign-up,
sign-up code, waitlist, age question and logout pages and their error
pages, carries:

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `same-origin` |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains`, when the issuer is https |

The pages run no script and no inline style. Browsers check `form-action`
on every redirect that follows a form submission, so a page whose form
ends at another origin adds it: the consent page adds the origins of the
client's redirect URIs, the logout page the `allowed_redirect_origins`,
and the age question, whose answer continues through the upstream
provider, `https:`. `same-origin` keeps page URLs, such as one carrying an
invite code, from reaching a provider or an application as a referrer,
while a same-origin form post keeps the `Origin` header the form handlers
check. The organization console sets its own policy.

A proxy in front of SystemAuth should pass these headers through rather
than replace them.

## Health checks

| Endpoint | Meaning |
|----------|---------|
| `GET /healthz` | Liveness: `200 {"status":"ok"}` while the process serves HTTP |
| `GET /readyz` | Readiness: `200` when every check passes (the binary registers a database ping), otherwise `503 {"status":"unavailable","checks":{"database":"fail"}}`; details are logged, not returned |

Embedding applications add their own checks with
`systemauth.WithReadinessCheck(name, func(ctx) error)`.

## DPoP

SystemAuth issues DPoP-bound tokens (RFC 9449): every client must send a DPoP
proof with its token requests unless its registration sets the legacy
`allow_bearer_tokens` exception. See [DPoP Enforcement](../session/dpop.md).
Outside `--dev` the server refuses to start unless the replay cache that
rejects reused proofs is shared by every instance, or one instance is
declared. With one instance:

```yaml
dpop:
  single_instance: true
```

When several instances serve SystemAuth, share the cache:

```yaml
dpop:
  replay_cache_redis_url: ${SYSTEMAUTH_DPOP_REDIS_URL}   # redis://host:6379/0
  # Optional server nonces (RFC 9449 §8):
  # require_nonce: true
  # nonce_secret: ${SYSTEMAUTH_DPOP_NONCE_SECRET}         # 32+ bytes, same on every instance
  # External base URL of the APIs SystemAuth protects (Middleware,
  # BearerAccess), when a proxy strips a path prefix:
  # resource_base_url: https://example.com/api
```

Without `replay_cache_redis_url` the cache is in memory, which suits a single
instance only: with per-instance caches, a proof replayed to another
instance is accepted. An embedding host may instead pass
`systemauthsvc.Options.DPoPReplayCache`. An existing database gains the `sf_oauth_apps.allow_bearer_tokens`
column on startup migration (or with `migrations/0010_oauth_app_allow_bearer_tokens.sql`);
every existing application then requires DPoP until the column is set for it.

## Upgrading

Startup migrations (`--migrate`, default on) add new columns automatically —
for example the `subject` columns on `sf_oauth_auth_codes` / `sf_oauth_tokens`
and the now-nullable `sf_oauth_auth_codes.user_id`. Run `systemauth migrate`
first if the service user lacks DDL privileges.

### Client party column

Each OAuth application records its party in `sf_oauth_apps.party`
(`first_party`, `second_party` or `third_party`; see
[Client party](overview.md#client-party)). Startup migration adds the column
empty; an application without a party is read by its older `first_party` flag
(set means `first_party`, otherwise `third_party`), and clients from the
configuration file are rewritten with their party at startup. Without startup
migration, run `migrations/0012_oauth_app_party.sql`, which also fills the
column from `first_party`. Then set `party` on any runtime-registered client
the operator owns (`first_party`) or a customer owns (`second_party`):
otherwise its users are asked for consent. `social_login.skip_consent` no
longer skips consent and can be removed.
