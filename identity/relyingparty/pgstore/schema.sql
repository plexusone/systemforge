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
