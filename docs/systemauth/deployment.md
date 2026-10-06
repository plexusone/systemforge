# Deploying SystemAuth

The `cmd/systemauth` binary is a self-contained SystemAuth server suitable for
running under a process supervisor (systemd) behind a TLS-terminating reverse
proxy (Caddy, nginx).

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
| `--dev` | `SYSTEMAUTH_DEV` | `false` | Development mode |
| `--log-level`, `--log-format` | `SYSTEMAUTH_LOG_LEVEL`, `SYSTEMAUTH_LOG_FORMAT` | `info`, `text` | Use `json` under a log collector |

`systemauth validate` checks a configuration, including the production
requirements; `systemauth migrate` runs migrations only.

## Signing key

Generate a key once and keep it in your secret store:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out systemauth-signing.pem
```

Provide it as a file readable only by the service user, or as PEM content in
`SYSTEMAUTH_SIGNING_KEY`. The JWKS `kid` defaults to the key's RFC 7638
thumbprint, so rotating the key changes the `kid` and relying parties fetch the
new JWKS on the first token signed with it. Tokens signed with the old key stop
verifying once it is replaced (overlapping keys are not supported yet).

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
