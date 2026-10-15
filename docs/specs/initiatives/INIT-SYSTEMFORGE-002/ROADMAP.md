# ROADMAP — SystemForge Migration — grokify to plexusone

**Initiative:** `INIT-SYSTEMFORGE-002`
**Repository:** `github.com/plexusone/systemforge`

This initiative completes the migration: GitHub transfer, module-path change,
history hygiene, and updating every consumer. Known consumers: dashforge,
actionforge, agentforge, uiforge, omniroadmap, proofminds-web, academyos.
Do this before `INIT-CROSSFORGE-001` Phase 3 so crossforge integrations land
on the final import path.

## Phase 1 — Repository & Module Migration

**Theme:** Move the module identity, clean the history, tag at the new path

- [ ] `RMI-SYSTEMFORGE-007` History hygiene: purge the stray 62 MB `coreauth` binary from the repository, verify clone size, add ignore rule
- [ ] `RMI-SYSTEMFORGE-008` GitHub transfer grokify→plexusone and module path change to github.com/plexusone/systemforge: rewrite internal imports, docs, badges, mkdocs URLs; verify old-path git redirect; tag next minor (v0.10.0)
  - Depends on: `RMI-SYSTEMFORGE-007`
- [ ] `RMI-SYSTEMFORGE-009` Deprecation notice at the old path: final grokify-path tag with Deprecated module comment pointing to github.com/plexusone/systemforge; README migration note
  - Depends on: `RMI-SYSTEMFORGE-008`
- [ ] `RMI-SYSTEMFORGEWEB-004` systemforge-web migration: GitHub transfer, module/package references to the plexusone path, CI workflows, docs
  - Depends on: `RMI-SYSTEMFORGE-008`

## Phase 2 — Consumer Updates

**Theme:** Seven consumers to the new import path, no local replaces pushed

- [ ] `RMI-DASHFORGE-017` dashforge: update systemforge imports (go.mod + authz/multiapp/session call sites) to plexusone path, bump to v0.10.0
  - Depends on: `RMI-SYSTEMFORGE-008`
- [ ] `RMI-ACTIONFORGE-039` actionforge: update systemforge imports to the plexusone path, remove any local module replace before push per pre-push checklist
  - Depends on: `RMI-SYSTEMFORGE-008`
- [ ] `RMI-AGENTFORGE-002` agentforge: update systemforge session/bff and session/oauth imports to plexusone path
  - Depends on: `RMI-SYSTEMFORGE-008`
- [ ] `RMI-UIFORGE-057` uiforge: decide migrate-or-archive for the pre-rename repo; if kept, update imports, else archive with pointer to dashforge
  - Depends on: `RMI-SYSTEMFORGE-008`
- [ ] `RMI-OMNIROADMAP-029` omniroadmap: update systemforge imports to plexusone path
  - Depends on: `RMI-SYSTEMFORGE-008`
- [ ] `RMI-PROOFMINDSWEB-001` proofminds-web: update systemforge imports to plexusone path (external vertical-app consumer — validates the standalone-use story)
  - Depends on: `RMI-SYSTEMFORGE-008`
- [ ] `RMI-ACADEMYOS-001` academyos: update systemforge imports including the multiapp adapter references to plexusone path
  - Depends on: `RMI-SYSTEMFORGE-008`
- [ ] `RMI-SYSTEMFORGE-010` Migration close-out: all seven consumers build against v0.10.0 with no replaces; INIT-SYSTEMFORGE-001 records updated; README positioning note
  - Depends on: `RMI-DASHFORGE-017`
  - Depends on: `RMI-ACTIONFORGE-039`
  - Depends on: `RMI-AGENTFORGE-002`
  - Depends on: `RMI-UIFORGE-057`
  - Depends on: `RMI-OMNIROADMAP-029`
  - Depends on: `RMI-PROOFMINDSWEB-001`
  - Depends on: `RMI-ACADEMYOS-001`
