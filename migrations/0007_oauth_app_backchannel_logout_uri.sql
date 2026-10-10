-- Let an OAuth application register an endpoint for back-channel events.
--
-- sf_oauth_apps.backchannel_logout_uri is where SystemAuth sends the
-- application OIDC Back-Channel Logout tokens, which also carry the
-- access-change events of ADR-010. Run it against an existing database when
-- deploying this version. A fresh database needs nothing. It is safe to run
-- more than once and changes no row: the column is nullable, and an
-- application without a value receives no events, as before. Without it,
-- reading or writing an application fails on the missing column.
-- Postgres syntax; for a SQLite development database, recreate it.

ALTER TABLE sf_oauth_apps ADD COLUMN IF NOT EXISTS backchannel_logout_uri varchar;
