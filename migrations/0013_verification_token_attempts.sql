-- Count the attempts made against a verification token.
--
-- sf_verification_tokens.attempts is how many guesses an email one-time
-- code sign-in has spent on a token; the token stops accepting attempts at
-- its limit. Run it against an existing database when deploying this
-- version. A fresh database needs nothing. It is safe to run more than
-- once. Existing tokens start at zero. Without the column, reading or
-- writing a verification token fails. Postgres syntax; for a SQLite
-- development database, recreate it.

ALTER TABLE sf_verification_tokens ADD COLUMN IF NOT EXISTS attempts bigint NOT NULL DEFAULT 0;
