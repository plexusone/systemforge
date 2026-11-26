-- Count the attempts made against a verification token.
--
-- sf_verification_tokens.attempts is how many guesses an email one-time
-- code sign-in has spent on a token; the token stops accepting attempts at
-- its limit. Run it against an existing PostgreSQL database that already
-- has sf_verification_tokens and every earlier migration, when deploying
-- this version; a database from before that table existed needs the schema
-- migration (systemauth migrate), which creates it. A fresh database needs
-- nothing. It is safe to run more than once. Existing tokens start at zero.
-- Without the column, reading or writing a verification token fails.
-- PostgreSQL syntax; on SQLite use the schema migration, or recreate a
-- development database.

ALTER TABLE sf_verification_tokens ADD COLUMN IF NOT EXISTS attempts bigint NOT NULL DEFAULT 0;
