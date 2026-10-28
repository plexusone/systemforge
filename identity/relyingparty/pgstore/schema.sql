-- SystemForge relying-party stores (PostgreSQL).
-- Idempotent: safe to run on every start. Applied by pgstore.EnsureSchema,
-- or copy it into your own migration tool.

-- Browser sessions. token_hash is the hex SHA-256 of the opaque cookie
-- token; the token itself is never stored. secrets holds the AES-256-GCM
-- encrypted SystemAuth tokens and claims, sealed with the key named by
-- key_id.
CREATE TABLE IF NOT EXISTS sf_rp_sessions (
    token_hash              text        PRIMARY KEY,
    principal_id            text        NOT NULL,
    subject                 text        NOT NULL DEFAULT '',
    sid                     text        NOT NULL DEFAULT '',
    key_id                  text        NOT NULL,
    secrets                 bytea       NOT NULL,
    access_token_expires_at timestamptz NULL,
    created_at              timestamptz NOT NULL,
    expires_at              timestamptz NOT NULL,
    updated_at              timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sf_rp_sessions_subject_idx
    ON sf_rp_sessions (subject) WHERE subject <> '';
CREATE INDEX IF NOT EXISTS sf_rp_sessions_sid_idx
    ON sf_rp_sessions (sid) WHERE sid <> '';
CREATE INDEX IF NOT EXISTS sf_rp_sessions_expires_at_idx
    ON sf_rp_sessions (expires_at);

-- In-flight logins, consumed exactly once by the OIDC callback. state_hash
-- is the hex SHA-256 of the OAuth state value; payload is the encrypted
-- nonce, PKCE verifier and return target.
CREATE TABLE IF NOT EXISTS sf_rp_login_states (
    state_hash text        PRIMARY KEY,
    key_id     text        NOT NULL,
    payload    bytea       NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS sf_rp_login_states_expires_at_idx
    ON sf_rp_login_states (expires_at);

-- The application's principals (relyingparty.PrincipalStore). id is the
-- app-local principal ID; sf_principal_id links it to SystemAuth (the OIDC
-- sub). email is NULL for a principal without one (a managed principal),
-- so the case-insensitive unique index ignores it.
CREATE TABLE IF NOT EXISTS sf_rp_principals (
    id              uuid        PRIMARY KEY,
    sf_principal_id text        NULL,
    type            text        NOT NULL DEFAULT 'human',
    email           text        NULL,
    email_verified  boolean     NOT NULL DEFAULT false,
    display_name    text        NOT NULL DEFAULT '',
    avatar_url      text        NOT NULL DEFAULT '',
    active          boolean     NOT NULL DEFAULT true,
    managed         boolean     NOT NULL DEFAULT false,
    last_login_at   timestamptz NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS sf_rp_principals_sf_principal_id_idx
    ON sf_rp_principals (sf_principal_id) WHERE sf_principal_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS sf_rp_principals_email_idx
    ON sf_rp_principals (lower(email)) WHERE email IS NOT NULL;
