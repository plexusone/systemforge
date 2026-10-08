-- Hash invite tokens at rest.
--
-- sf_invites.token now holds the hex SHA-256 of the invite link's token
-- instead of the token itself. This converts tokens stored by earlier
-- versions so their outstanding invite links keep working. A plain token
-- is 44 base64url characters and a hash is 64 hex characters, so the
-- statement converts each row once and is safe to run more than once.
--
-- Run it against an existing database when deploying this version. A
-- fresh database needs nothing. Postgres syntax (sha256 needs PostgreSQL
-- 11 or later). For a SQLite development database, revoke and resend
-- outstanding invites instead.

UPDATE sf_invites
SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex')
WHERE token !~ '^[0-9a-f]{64}$';
