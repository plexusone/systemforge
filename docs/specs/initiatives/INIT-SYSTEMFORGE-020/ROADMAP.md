# ROADMAP — A Service That Comes Up Correctly

**Initiative:** `INIT-SYSTEMFORGE-020`
**Repository:** `github.com/plexusone/systemforge`

Every application runs a continuous upgrade of SystemForge, so an upgrade that
the database is not ready for must fail at startup, with a message that names
the fix, not on a later request. Commits implementing an item carry
`Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Refuse to Start Behind

**Theme:** A schema that is behind this version stops the service before it serves

- [x] `RMI-SYSTEMFORGE-284` `systemauthsvc.CheckSchema` and `CheckMigrations`: compare the database's tables and columns with the identity schema on PostgreSQL and SQLite, and return `ErrSchemaBehind` naming what is missing and how to fix it
- [x] `RMI-SYSTEMFORGE-285` `systemauthsvc.New` runs the check when migrations are not run, refusing to start behind; `Options.SkipSchemaCheck` opts out
  - Depends on: `RMI-SYSTEMFORGE-284`
- [x] `RMI-SYSTEMFORGE-286` `systemauth migrate --check`, so a deploy can verify the schema before starting the new version
  - Depends on: `RMI-SYSTEMFORGE-284`
- [x] `RMI-SYSTEMFORGE-287` Release v0.39.0: notes, changelog, guides
  - Depends on: `RMI-SYSTEMFORGE-285`, `RMI-SYSTEMFORGE-286`
