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

and it rejects `social_login.insecure_cookies`. `--dev` relaxes all of these
(ephemeral key, in-memory storage, `http://localhost` issuer).

With a database configured, social login sessions, in-flight upstream logins
and consent grants are stored in it (`sf_login_sessions`, `sf_login_states`,
`sf_consent_grants`), so restarts keep users signed in and several instances
can run behind a load balancer on one PostgreSQL database. Statically
configured clients are updated from the configuration on each start. See
[Production Stores](production-stores.md).

## Flags and environment

Running `systemauth` without a subcommand serves. Go-style single-dash flags
(`-addr`) are accepted, and every flag can be set from an environment variable
when it is not on the command line:

| Flag | Environment | Default | Notes |
|------|-------------|---------|-------|
| `--config`, `-c` | `SYSTEMAUTH_CONFIG` | — | YAML/JSON config; `${ENV}` references are expanded |
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

## Invite-only sign-up

Start with `--invite-only` to let new accounts in only by invitation, for
example while a deployment is being brought up. An invite is an email address,
not a code: the person signs in with the upstream provider, and an account is
created only when the provider's **verified** email holds a pending invite.
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
  reads the list with `Service.SignupWaitlist()`. Behind a proxy, pass the
  client-address function (`WithLoginTokenClientIP`) so the per-address
  limit sees real clients.
- **Database:** the commands read the configured database directly, so they
  work with the server running. The table is created by the schema migration.
- **In a host binary,** set `Options.InviteOnly` and `Options.SignupDeniedURL`
  on `systemauthsvc.New`, and manage invites with `Service.SignupInvites()`.

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

Caddy terminates TLS and proxies to the loopback listener:

```
auth.example.com {
    reverse_proxy 127.0.0.1:8081
}
```

## Health checks

| Endpoint | Meaning |
|----------|---------|
| `GET /healthz` | Liveness: `200 {"status":"ok"}` while the process serves HTTP |
| `GET /readyz` | Readiness: `200` when every check passes (the binary registers a database ping), otherwise `503 {"status":"unavailable","checks":{"database":"fail"}}`; details are logged, not returned |

Embedding applications add their own checks with
`systemauth.WithReadinessCheck(name, func(ctx) error)`.

## Upgrading

Startup migrations (`--migrate`, default on) add new columns automatically —
for example the `subject` columns on `sf_oauth_auth_codes` / `sf_oauth_tokens`
and the now-nullable `sf_oauth_auth_codes.user_id`. Run `systemauth migrate`
first if the service user lacks DDL privileges.
