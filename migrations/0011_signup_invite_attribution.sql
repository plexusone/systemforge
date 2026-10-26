-- Record who created a sign-up invite and when a waitlist entry was invited.
--
-- Run it against an existing database when deploying this version. A fresh
-- database needs nothing. It is safe to run more than once. Without it,
-- reading or writing sign-up invites and waitlist entries fails on the
-- missing columns. The new tables for invite codes, their redemptions and
-- member allowances (sf_signup_codes, sf_signup_code_redemptions,
-- sf_signup_allowances) are created by the schema migration.
-- Postgres syntax; for a SQLite development database, recreate it.

ALTER TABLE sf_signup_invites ADD COLUMN IF NOT EXISTS invited_by_principal_id uuid NULL;
ALTER TABLE sf_signup_waitlist ADD COLUMN IF NOT EXISTS invited_at timestamp with time zone NULL;
