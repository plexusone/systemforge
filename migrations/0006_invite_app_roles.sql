-- Let an invite carry the application roles to grant on acceptance.
--
-- sf_invites.app_roles holds a JSON object from application identifier to
-- role, chosen by the inviter per application (ADR-007). Run it against an
-- existing database when deploying this version. A fresh database needs
-- nothing. It is safe to run more than once and changes no row: the column
-- is nullable, and an invite without it grants no application role, as
-- before. Without it, creating an invite fails on the missing column.
-- Postgres syntax; for a SQLite development database, recreate it.

ALTER TABLE sf_invites ADD COLUMN IF NOT EXISTS app_roles jsonb;
