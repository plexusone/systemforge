# Migration Guide

This guide covers moving an existing application's users, organizations, and memberships into SystemForge's identity tables.

## Target Model

SystemForge has a single identity root. Every person is a **principal**:

| Concept | Table | Notes |
|---------|-------|-------|
| Person | `sf_principals` (`type = 'human'`) + `sf_humans` | `sf_principals.identifier` is the email; `sf_humans.principal_id` links the two |
| Password | `sf_credentials` (`type = 'password'`) | Argon2id hash in `secret_hash` |
| Social or SSO login | `sf_external_identities` | One row per `(provider, subject)` |
| Organization | `sf_organizations` | |
| Membership | `sf_principal_memberships` | One row per `(principal_id, organization_id)` |

All tables use the `sf_` prefix. See the [schema reference](../reference/schemas.md) for every column.

## Migration Strategy

### Phase 1: Side-by-Side

- Create the SystemForge tables alongside your existing ones.
- Copy existing users, organizations, and memberships.
- Write new data to both until reads move over.

### Phase 2: Cutover

- Switch reads to SystemForge.
- Validate counts and spot-check records.
- Stop writing to the old tables.

### Phase 3: Cleanup

- Archive the old tables.
- Drop them once nothing reads them.
- Remove the dual-write code.

## Creating SystemForge Tables

### Using the SystemAuth CLI

```bash
systemauth migrate
```

This creates or updates every table from the current schema and is safe to run repeatedly.

### Using Ent Directly

```go
package main

import (
    "context"
    "database/sql"
    "log"

    "entgo.io/ent/dialect"
    entsql "entgo.io/ent/dialect/sql"
    _ "github.com/jackc/pgx/v5/stdlib"

    "github.com/plexusone/systemforge/identity/ent"
)

func main() {
    db, err := sql.Open("pgx", "postgres://user:pass@localhost/myapp?sslmode=disable")
    if err != nil {
        log.Fatal(err)
    }
    client := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))
    defer client.Close()

    if err := client.Schema.Create(context.Background()); err != nil {
        log.Fatal(err)
    }
    log.Println("SystemForge tables created")
}
```

Ent's migration creates and alters tables and columns but never drops them.

## Copying Data

The examples below use PostgreSQL and copy from `users`, `tenants`, and `tenant_members` tables; adapt the source queries to your schema. Several columns have no database default because Ent fills them in Go, so the inserts set them explicitly:

- `id` on `sf_humans`, `sf_credentials`, and `sf_principal_memberships`
- `created_at` and `updated_at`
- `capabilities` (JSON object) and `allowed_scopes` (JSON array) on `sf_principals`
- `scopes` (JSON array) on `sf_credentials`

### Users

Each user becomes a principal plus a human row. Reusing the existing user ID as the principal ID keeps foreign keys in your application valid.

```go
func copyUsers(ctx context.Context, src, dst *sql.DB) error {
    rows, err := src.QueryContext(ctx, `
        SELECT id, email, name, COALESCE(avatar_url, ''), created_at
        FROM users
        WHERE deleted_at IS NULL
    `)
    if err != nil {
        return err
    }
    defer rows.Close()

    tx, err := dst.BeginTx(ctx, nil)
    if err != nil {
        return err
    }
    defer tx.Rollback()

    count := 0
    for rows.Next() {
        var id uuid.UUID
        var email, name, avatar string
        var createdAt time.Time
        if err := rows.Scan(&id, &email, &name, &avatar, &createdAt); err != nil {
            return err
        }

        if _, err := tx.ExecContext(ctx, `
            INSERT INTO sf_principals
                (id, created_at, updated_at, type, identifier, display_name, active, capabilities, allowed_scopes)
            VALUES ($1, $2, $2, 'human', $3, $4, true, '{}', '[]')
            ON CONFLICT (id) DO UPDATE SET
                identifier = EXCLUDED.identifier,
                display_name = EXCLUDED.display_name,
                updated_at = now()
        `, id, createdAt, email, name); err != nil {
            return fmt.Errorf("copy principal %s: %w", id, err)
        }

        if _, err := tx.ExecContext(ctx, `
            INSERT INTO sf_humans (id, created_at, updated_at, principal_id, email, avatar_url)
            VALUES (gen_random_uuid(), $2, $2, $1, $3, NULLIF($4, ''))
            ON CONFLICT (principal_id) DO UPDATE SET
                email = EXCLUDED.email,
                avatar_url = EXCLUDED.avatar_url,
                updated_at = now()
        `, id, createdAt, email, avatar); err != nil {
            return fmt.Errorf("copy human %s: %w", id, err)
        }
        count++
    }
    if err := rows.Err(); err != nil {
        return err
    }
    if err := tx.Commit(); err != nil {
        return err
    }
    log.Printf("copied %d users", count)
    return nil
}
```

Before copying, check your source for emails that differ only in case. SystemForge looks people up by email without regard to case, so two rows such as `Ada@example.com` and `ada@example.com` make that lookup ambiguous. Merge or rename them first:

```sql
SELECT lower(email), count(*)
FROM users
WHERE deleted_at IS NULL
GROUP BY lower(email)
HAVING count(*) > 1;
```

### Passwords

Passwords are `sf_credentials` rows of type `password`. SystemForge verifies **only** Argon2id hashes in the standard encoded form:

```
$argon2id$v=19$m=<memory>,t=<iterations>,p=<parallelism>$<salt>$<hash>
```

where the salt and hash are unpadded standard base64. Any parameters are accepted; they are read from the hash. A hash in any other format (bcrypt, scrypt, PBKDF2, Argon2i) is rejected at login with an error, so do not import it. Leave those users without a password credential and have them reset their password, which stores a new Argon2id hash.

```sql
INSERT INTO sf_credentials
    (id, created_at, updated_at, principal_id, type, secret_hash, scopes, active, revoked)
SELECT gen_random_uuid(), now(), now(), u.id, 'password', u.password_hash, '[]', true, false
FROM users u
WHERE u.deleted_at IS NULL
  AND u.password_hash LIKE '$argon2id$v=19$%'
  AND NOT EXISTS (
      SELECT 1 FROM sf_credentials c
      WHERE c.principal_id = u.id AND c.type = 'password'
  );
```

To set passwords from application code instead, use the credential service, which hashes with Argon2id:

```go
creds := credential.NewService(client)
err := creds.CreatePassword(ctx, credential.CreatePasswordInput{
    PrincipalID: principalID,
    Password:    plaintext,
})
```

### Organizations

```sql
INSERT INTO sf_organizations
    (id, created_at, updated_at, name, slug, org_type, plan, active)
SELECT t.id, t.created_at, now(), t.name, t.slug, 'team', 'free', true
FROM tenants t
WHERE t.deleted_at IS NULL
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    updated_at = now();
```

`org_type` is one of `personal`, `team`, or `enterprise`; `plan` is one of `free`, `starter`, `pro`, or `enterprise`.

### Memberships

`role` is an application-defined string.

```sql
INSERT INTO sf_principal_memberships
    (id, created_at, updated_at, principal_id, organization_id, role, active)
SELECT gen_random_uuid(), m.created_at, now(), m.user_id, m.tenant_id, m.role, true
FROM tenant_members m
JOIN sf_principals p ON p.id = m.user_id
JOIN sf_organizations o ON o.id = m.tenant_id
ON CONFLICT (principal_id, organization_id) DO UPDATE SET
    role = EXCLUDED.role,
    active = true,
    updated_at = now();
```

## Validation Queries

### Compare Counts

```sql
-- People
SELECT
    (SELECT count(*) FROM users WHERE deleted_at IS NULL) AS old_count,
    (SELECT count(*) FROM sf_principals WHERE type = 'human') AS new_count;

-- Organizations
SELECT
    (SELECT count(*) FROM tenants WHERE deleted_at IS NULL) AS old_count,
    (SELECT count(*) FROM sf_organizations) AS new_count;

-- Memberships
SELECT
    (SELECT count(*) FROM tenant_members) AS old_count,
    (SELECT count(*) FROM sf_principal_memberships) AS new_count;
```

### Find Missing Records

```sql
-- Users in the old table with no SystemForge principal
SELECT u.id, u.email
FROM users u
LEFT JOIN sf_principals p ON p.id = u.id
WHERE u.deleted_at IS NULL AND p.id IS NULL;

-- Principals missing their human row
SELECT p.id, p.identifier
FROM sf_principals p
LEFT JOIN sf_humans h ON h.principal_id = p.id
WHERE p.type = 'human' AND h.id IS NULL;
```

### Compare Data

```sql
SELECT u.id, u.email AS old_email, h.email AS new_email
FROM users u
JOIN sf_humans h ON h.principal_id = u.id
WHERE u.email <> h.email;
```

## Rollback Plan

### Keep the Old Tables in Sync

During the dual-write phase, mirror SystemForge changes back to the old tables so reads can move back if needed:

```go
func mirrorToOldTable(ctx context.Context, oldDB *sql.DB, p *ent.Principal) error {
    if p.Edges.Human == nil {
        return fmt.Errorf("principal %s loaded without its human edge", p.ID)
    }
    _, err := oldDB.ExecContext(ctx, `
        UPDATE users SET email = $2, name = $3, updated_at = now()
        WHERE id = $1
    `, p.ID, p.Edges.Human.Email, p.DisplayName)
    return err
}
```

Load the principal with its human edge, for example `client.Principal.Query().Where(principal.IDEQ(id)).WithHuman().Only(ctx)`.

### Switch Reads Back

Gate reads behind a flag so they can move back to the old tables without a deploy:

```go
var useOldTables = os.Getenv("USE_OLD_TABLES") == "true"
```

## Archive and Cleanup

### Archive Old Tables

```sql
CREATE SCHEMA archive;

ALTER TABLE users SET SCHEMA archive;
ALTER TABLE tenants SET SCHEMA archive;
ALTER TABLE tenant_members SET SCHEMA archive;
```

### Drop After Validation

```sql
DROP SCHEMA archive CASCADE;
```

## Common Issues

### Integer User IDs

Principal IDs are UUIDs. If your old tables use integers, generate a mapping first and use `new_id` everywhere a principal ID is needed:

```sql
CREATE TABLE user_id_mapping (
    old_id BIGINT PRIMARY KEY,
    new_id UUID NOT NULL UNIQUE
);

INSERT INTO user_id_mapping (old_id, new_id)
SELECT id, gen_random_uuid()
FROM users;
```

### Password Hashes in Another Format

Only Argon2id hashes in the encoded form above can be imported. Users whose hashes use another algorithm must reset their password after the migration.
