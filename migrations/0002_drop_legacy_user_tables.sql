-- One-time cleanup for an existing dev database created before the legacy
-- User model was retired (ADR-004).
--
-- Humans now live only in sf_principals + sf_humans. The legacy tables
-- (sf_users and the tables that existed only to support it) are no longer
-- part of the schema, and Ent's auto-migration never drops tables or
-- columns, so an existing database keeps them until this script runs. No
-- production data exists in these tables, so a fresh database needs no
-- migration at all -- just run `systemauth migrate`.
--
-- Run this ONLY against an existing dev database with data you want to keep,
-- and run it BEFORE starting the new version or running `systemauth migrate`:
-- the new schema adds foreign keys from sf_oauth_apps.owner_id and
-- sf_oauth_consents.principal_id to sf_principals, which fail if rows still
-- point at legacy users. Safe to run more than once.
--
-- What it does, in order:
--   1. Creates the system service principal that now owns statically
--      configured OAuth clients, at the same fixed ID the legacy system
--      user used, so existing owner_id values stay valid.
--   2. Reassigns any other OAuth app owned by a legacy user to that
--      principal (legacy user IDs are not principal IDs).
--   3. Drops the legacy user columns from the OAuth tables. Rows in
--      sf_oauth_consents are deleted: no code path reads or writes that
--      table, and its new principal_id column is required.
--   4. Drops the legacy tables.
--
-- Postgres syntax. For a SQLite dev database, drop and recreate it instead.

BEGIN;

-- 1. System service principal.
INSERT INTO sf_principals
    (id, created_at, updated_at, type, identifier, display_name, active, capabilities, allowed_scopes)
VALUES
    ('00000000-0000-0000-0000-000000000001', now(), now(), 'service',
     'system@systemauth.local', 'SystemAuth System', true, '{}', '[]')
ON CONFLICT DO NOTHING;

INSERT INTO sf_service_principals
    (id, created_at, updated_at, service_type, description, allowed_ips, principal_id)
SELECT gen_random_uuid(), now(), now(), 'systemauth',
       'Owns OAuth clients defined in SystemAuth configuration', '[]',
       '00000000-0000-0000-0000-000000000001'
WHERE NOT EXISTS (
    SELECT 1 FROM sf_service_principals
    WHERE principal_id = '00000000-0000-0000-0000-000000000001'
);

-- 2. OAuth apps owned by legacy users.
UPDATE sf_oauth_apps
SET owner_id = '00000000-0000-0000-0000-000000000001'
WHERE owner_id NOT IN (SELECT id FROM sf_principals);

-- 3. Legacy user columns on the OAuth tables.
ALTER TABLE IF EXISTS sf_oauth_tokens DROP COLUMN IF EXISTS user_id;
ALTER TABLE IF EXISTS sf_oauth_tokens DROP COLUMN IF EXISTS service_account_id;
ALTER TABLE IF EXISTS sf_oauth_auth_codes DROP COLUMN IF EXISTS user_id;
DELETE FROM sf_oauth_consents;
ALTER TABLE IF EXISTS sf_oauth_consents DROP COLUMN IF EXISTS user_id;

-- 4. Legacy tables. CASCADE removes the foreign keys that point at them.
DROP TABLE IF EXISTS sf_service_account_key_pairs CASCADE;
DROP TABLE IF EXISTS sf_service_accounts CASCADE;
DROP TABLE IF EXISTS sf_api_keys CASCADE;
DROP TABLE IF EXISTS sf_refresh_tokens CASCADE;
DROP TABLE IF EXISTS sf_oauth_accounts CASCADE;
DROP TABLE IF EXISTS sf_memberships CASCADE;
DROP TABLE IF EXISTS sf_users CASCADE;

COMMIT;
