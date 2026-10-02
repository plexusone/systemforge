-- One-time rename for an existing dev database created before v0.11.0.
--
-- v0.11.0 renamed the cf_ table prefix to sf_ (ADR-001: Core-era naming
-- cleanup). This is a hard cutover with no dual-name compatibility: no
-- production data exists at this prefix, so a fresh database needs no
-- migration at all -- just run `systemauth migrate` to create the sf_
-- tables from the current schema.
--
-- Run this ONLY against an existing dev database that already has cf_
-- tables with data you want to keep. Safe to run more than once: a
-- second run is a no-op once every table has been renamed, since
-- "IF EXISTS" guards each statement.
--
-- Postgres syntax ("ALTER TABLE IF EXISTS ... RENAME TO"). For a SQLite
-- or MySQL dev database, it is simpler to drop and recreate it (see
-- above) than to translate this to each dialect's rename syntax.

ALTER TABLE IF EXISTS cf_agents RENAME TO sf_agents;
ALTER TABLE IF EXISTS cf_api_keys RENAME TO sf_api_keys;
ALTER TABLE IF EXISTS cf_applications RENAME TO sf_applications;
ALTER TABLE IF EXISTS cf_credentials RENAME TO sf_credentials;
ALTER TABLE IF EXISTS cf_humans RENAME TO sf_humans;
ALTER TABLE IF EXISTS cf_invites RENAME TO sf_invites;
ALTER TABLE IF EXISTS cf_licenses RENAME TO sf_licenses;
ALTER TABLE IF EXISTS cf_listings RENAME TO sf_listings;
ALTER TABLE IF EXISTS cf_memberships RENAME TO sf_memberships;
ALTER TABLE IF EXISTS cf_oauth_accounts RENAME TO sf_oauth_accounts;
ALTER TABLE IF EXISTS cf_oauth_apps RENAME TO sf_oauth_apps;
ALTER TABLE IF EXISTS cf_oauth_app_secrets RENAME TO sf_oauth_app_secrets;
ALTER TABLE IF EXISTS cf_oauth_auth_codes RENAME TO sf_oauth_auth_codes;
ALTER TABLE IF EXISTS cf_oauth_consents RENAME TO sf_oauth_consents;
ALTER TABLE IF EXISTS cf_oauth_tokens RENAME TO sf_oauth_tokens;
ALTER TABLE IF EXISTS cf_organizations RENAME TO sf_organizations;
ALTER TABLE IF EXISTS cf_principals RENAME TO sf_principals;
ALTER TABLE IF EXISTS cf_principal_memberships RENAME TO sf_principal_memberships;
ALTER TABLE IF EXISTS cf_principal_tokens RENAME TO sf_principal_tokens;
ALTER TABLE IF EXISTS cf_refresh_tokens RENAME TO sf_refresh_tokens;
ALTER TABLE IF EXISTS cf_seat_assignments RENAME TO sf_seat_assignments;
ALTER TABLE IF EXISTS cf_service_accounts RENAME TO sf_service_accounts;
ALTER TABLE IF EXISTS cf_service_account_key_pairs RENAME TO sf_service_account_key_pairs;
ALTER TABLE IF EXISTS cf_service_principals RENAME TO sf_service_principals;
ALTER TABLE IF EXISTS cf_subscriptions RENAME TO sf_subscriptions;
ALTER TABLE IF EXISTS cf_users RENAME TO sf_users;
