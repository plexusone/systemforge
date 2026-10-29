-- Record who owns each OAuth application: its party.
--
-- sf_oauth_apps.party is first_party (the service provider owns the
-- application), second_party (the customer owns it) or third_party (a
-- partner owns it); the customer owns the data in every case. SystemAuth
-- skips the consent screen only for first-party applications. Run it
-- against an existing database when deploying this version. A fresh
-- database needs nothing. It is safe to run more than once. Each existing
-- application gets first_party when its first_party flag is set and
-- third_party otherwise, so it is asked for consent; set second_party or
-- first_party where that is wrong. Clients declared in the SystemAuth
-- configuration file are rewritten from it at startup, as first_party unless
-- they state a party. Without the column, reading or writing an application
-- fails. Postgres syntax; for a SQLite development database, recreate it.

ALTER TABLE sf_oauth_apps ADD COLUMN IF NOT EXISTS party varchar;
UPDATE sf_oauth_apps
   SET party = CASE WHEN first_party THEN 'first_party' ELSE 'third_party' END
 WHERE party IS NULL;
