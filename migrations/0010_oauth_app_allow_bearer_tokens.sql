-- Record which OAuth applications may still get unbound bearer tokens.
--
-- SystemAuth issues DPoP-bound tokens (RFC 9449): every token request must
-- carry a DPoP proof unless the application's sf_oauth_apps.allow_bearer_tokens
-- is set, a legacy exception. Run it against an existing database when
-- deploying this version. A fresh database needs nothing. It is safe to run
-- more than once. Every existing application gets false, so from this
-- version on it must send DPoP proofs; set the column for an application
-- that cannot yet. Without it, reading or writing an application fails on
-- the missing column.
-- Postgres syntax; for a SQLite development database, recreate it.

ALTER TABLE sf_oauth_apps ADD COLUMN IF NOT EXISTS allow_bearer_tokens boolean NOT NULL DEFAULT false;
