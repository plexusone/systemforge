-- Drop the organization plan column.
--
-- sf_organizations.plan was a placeholder from before the marketplace: it
-- was set at creation and never consulted for access, and one value cannot
-- describe an organization holding several subscriptions or licenses. What
-- an organization may use now derives from its marketplace subscriptions
-- and licenses, and a plan's name lives on its listing.
--
-- Run it against an existing database when deploying this version. A fresh
-- database needs nothing. It is safe to run more than once, and it loses
-- nothing the system read. Without it the old column stays, unused: new
-- rows take its stored default. Postgres syntax; for a SQLite development
-- database, recreate it.

ALTER TABLE sf_organizations DROP COLUMN IF EXISTS plan;
