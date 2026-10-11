-- Let an invite target one resource.
--
-- sf_invites.resource_type, resource_id and resource_role name a resource
-- and the resource role to grant on acceptance (ADR-008). Accepting such an
-- invite creates the collaborator membership and the grant in one
-- transaction. Run it against an existing database when deploying this
-- version. A fresh database needs nothing. It is safe to run more than
-- once and changes no row: the columns are nullable, and an invite without
-- them is an organization invite, as before. Without it, creating an
-- invite fails on the missing columns. The sf_resource_grants table is new
-- and is created by the schema migration. Postgres syntax; for a SQLite
-- development database, recreate it.

ALTER TABLE sf_invites ADD COLUMN IF NOT EXISTS resource_type varchar(128);
ALTER TABLE sf_invites ADD COLUMN IF NOT EXISTS resource_id varchar(1024);
ALTER TABLE sf_invites ADD COLUMN IF NOT EXISTS resource_role varchar(255);
