# Production Stores

SystemAuth and relying parties keep short-lived browser state server-side:
login sessions, in-flight OAuth logins and consent decisions on SystemAuth,
and application sessions (holding SystemAuth tokens) and in-flight logins on
each relying party. The defaults are in-memory, which is fine for a single
development process but means a restart signs everyone out and replicas do
not share state. In production, use the durable stores described here.

## SystemAuth

When SystemAuth runs on `EntStorage` (any `database` configured for the
`systemauth` binary), social login automatically uses database-backed stores.
Nothing needs to be configured:

| Store | Implementation | Table |
|-------|----------------|-------|
| Login sessions (`__Host-sf_login`) | `EntLoginSessionStore` | `sf_login_sessions` |
| Upstream login state | `EntLoginStateStore` | `sf_login_states` |
| Consent grants | `EntConsentStore` | `sf_consent_grants` |

The tables are part of SystemAuth's Ent schema and are created by
`systemauth migrate` (or `--migrate` on `serve`). Without a database
(`--dev`), the in-memory stores are used and a warning is logged.

Behavior:

- Session tokens and OAuth state values are stored only as SHA-256 hashes.
  The upstream nonce and PKCE verifier are stored for the duration of the
  login (at most 10 minutes) and deleted when the callback consumes them.
- `Take` on the login state is single-use across replicas: a row is returned
  only to the caller whose delete removed it.
- Consent is one row per (principal, client, scope), so concurrent grants
  from several replicas never lose scopes.
- Expired rows are removed opportunistically on writes, at most once every
  5 minutes per instance. A scheduled job can also call `DeleteExpired`.

Library users embedding SystemAuth get the same defaults with
`WithStorage(NewEntStorage(client))`, and can construct the stores directly:

```go
sessions := systemauth.NewEntLoginSessionStore(entClient,
    systemauth.WithCleanupInterval(10*time.Minute)) // 0 disables
srv, err := systemauth.NewEmbedded(cfg,
    systemauth.WithStorage(systemauth.NewEntStorage(entClient)),
    systemauth.WithLoginSessionStore(sessions),
    systemauth.WithLoginStateStore(systemauth.NewEntLoginStateStore(entClient)),
    systemauth.WithConsentStore(systemauth.NewEntConsentStore(entClient)),
)
```

The Ent stores work on PostgreSQL (recommended for multiple replicas) and
SQLite (single instance that survives restarts).

## Relying parties

Relying parties own their database and do not depend on SystemAuth's
schema. The `identity/relyingparty/pgstore` package provides PostgreSQL
implementations of `relyingparty.SessionStore` and
`relyingparty.LoginStateStore` on `database/sql` with the pgx driver:

| Store | Constructor | Table |
|-------|-------------|-------|
| Browser sessions | `pgstore.NewSessionStore` | `sf_rp_sessions` |
| In-flight logins | `pgstore.NewLoginStateStore` | `sf_rp_login_states` |

```go
import (
    _ "github.com/jackc/pgx/v5/stdlib"

    "github.com/plexusone/systemforge/identity/relyingparty"
    "github.com/plexusone/systemforge/identity/relyingparty/pgstore"
)

db, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
if err != nil {
    return err
}
if err := pgstore.EnsureSchema(ctx, db); err != nil {
    return err
}

key, err := pgstore.DecodeKey(os.Getenv("SESSION_ENCRYPTION_KEY"))
if err != nil {
    return err
}
keyOpt := pgstore.WithEncryptionKey("k1", key)

sessions, err := pgstore.NewSessionStore(db, keyOpt)
if err != nil {
    return err
}
states, err := pgstore.NewLoginStateStore(db, keyOpt)
if err != nil {
    return err
}

bff, err := relyingparty.NewBFF(relyingparty.BFFConfig{
    Client:      client,
    Principals:  principals,
    Sessions:    sessions,
    LoginStates: states,
})
```

### Schema

`EnsureSchema` applies `pgstore.SchemaSQL` idempotently, under an advisory
lock so replicas starting together do not race. Applications with their own
migration tool can copy `SchemaSQL` into a migration instead. Indexes cover
`expires_at` on both tables and `subject` and `sid` on sessions (used by
`DeleteBySubject` / `DeleteBySID` for back-channel logout).

### Encryption at rest

Session rows hold SystemAuth access, refresh and ID tokens. They, the
session's claims, and the login nonce and PKCE verifier are sealed with
AES-256-GCM before they reach the database:

- The key is supplied by the application (32 bytes; generate one with
  `openssl rand -base64 32` and keep it in a secret manager). `DecodeKey`
  accepts hex or base64.
- Each row records the ID of the key that sealed it. The ciphertext is bound
  to its table, row and key ID, so a value copied into another row or
  relabeled with another key fails to decrypt.
- The constructors refuse to start without `WithEncryptionKey`.
  `WithInsecurePlaintext()` allows plaintext for local development only.
- A row that fails decryption (tampered, or sealed with a key that is no
  longer configured) is logged and reported as an error wrapping both
  `relyingparty.ErrSessionNotFound` (the user is signed out) and
  `pgstore.ErrDecrypt` or `pgstore.ErrUnknownKeyID`.

Cookie tokens and OAuth state values are stored only as SHA-256 hashes.

### Key rotation

1. Deploy every instance with the new key as the encryption key and the old
   key as a decryption key:

    ```go
    pgstore.WithEncryptionKey("k2", newKey),
    pgstore.WithDecryptionKey("k1", oldKey),
    ```

2. New sessions are sealed with `k2`; existing ones are re-sealed with `k2`
   whenever they are updated (for example on token refresh).
3. After the session lifetime (default 12 hours) has passed, every `k1` row
   has expired or been re-sealed; remove the `WithDecryptionKey` option.

Keep the key ID stable for a given key: it is stored in every row.

### Cleanup

Both stores delete expired rows opportunistically on writes, at most once
every 5 minutes per instance (`pgstore.WithCleanupInterval`, `0` disables).
`DeleteExpired(ctx)` can be called from a scheduled job instead.

## Testing custom stores

`identity/systemauth/storetest` and `identity/relyingparty/storetest` are
conformance suites (round trip, expiry, single-use `Take` under concurrency,
back-channel deletes). Run them against any custom store implementation. The
PostgreSQL tests in this repository run when `SF_TEST_PG_DSN` points at a
server where the test user may create databases:

```bash
SF_TEST_PG_DSN='postgres://user@127.0.0.1:5432/postgres?sslmode=disable' go test ./...
```
