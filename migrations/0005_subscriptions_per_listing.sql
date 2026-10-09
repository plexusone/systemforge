-- Allow one subscription per listing, beside the platform subscription.
--
-- sf_subscriptions held at most one row per organization. A subscription
-- may now be for a marketplace listing (listing_id), so an organization
-- can hold one per listing plus at most one platform-wide subscription
-- (listing_id null). sf_listings also gains an optional application
-- column naming the registered application a listing entitles an
-- organization to.
--
-- Run it against an existing database when deploying this version. A fresh
-- database needs nothing. It is safe to run more than once and changes no
-- row: both new columns are nullable, every existing subscription becomes
-- the platform subscription, and the constraint it replaces is relaxed,
-- never tightened. Without it, a second subscription for an organization
-- is refused by the old unique constraint. Postgres syntax; for a SQLite
-- development database, recreate it.

ALTER TABLE sf_listings ADD COLUMN IF NOT EXISTS application varchar;
ALTER TABLE sf_subscriptions ADD COLUMN IF NOT EXISTS listing_id uuid;

-- Drop every unique constraint or index on organization_id alone,
-- whatever the earlier schema named it.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT con.conname
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        WHERE rel.relname = 'sf_subscriptions'
          AND con.contype = 'u'
          AND (SELECT array_agg(att.attname::text)
               FROM unnest(con.conkey) k
               JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = k)
              = ARRAY['organization_id']
    LOOP
        EXECUTE format('ALTER TABLE sf_subscriptions DROP CONSTRAINT %I', r.conname);
    END LOOP;

    FOR r IN
        SELECT idx.indexrelid::regclass::text AS name
        FROM pg_index idx
        JOIN pg_class rel ON rel.oid = idx.indrelid
        WHERE rel.relname = 'sf_subscriptions'
          AND idx.indisunique
          AND NOT idx.indisprimary
          AND idx.indnatts = 1
          AND idx.indpred IS NULL
          AND (SELECT att.attname FROM pg_attribute att
               WHERE att.attrelid = idx.indrelid AND att.attnum = idx.indkey[0]) = 'organization_id'
    LOOP
        EXECUTE format('DROP INDEX %s', r.name);
    END LOOP;
END $$;

CREATE INDEX IF NOT EXISTS subscription_organization_id ON sf_subscriptions (organization_id);
CREATE UNIQUE INDEX IF NOT EXISTS subscription_organization_id_listing_id ON sf_subscriptions (organization_id, listing_id);
CREATE UNIQUE INDEX IF NOT EXISTS subscription_platform_per_org ON sf_subscriptions (organization_id) WHERE listing_id IS NULL;
CREATE INDEX IF NOT EXISTS subscription_listing_id ON sf_subscriptions (listing_id);
CREATE INDEX IF NOT EXISTS listing_application ON sf_listings (application);
