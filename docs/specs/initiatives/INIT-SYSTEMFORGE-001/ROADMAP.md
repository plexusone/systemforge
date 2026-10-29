# ROADMAP — Unified Forge Platform — Authorization Contract, IAM Console, and Shell Composition

**Initiative:** `INIT-SYSTEMFORGE-001`
**Repository:** `github.com/plexusone/systemforge`

Cross-repo initiative: RMIs below span systemforge, systemforge-web, and the
three Forge apps (per-RMI repository noted; roadmap import assigns the
default repository, cross-repo RMIs are corrected after import).

## Phase 1 — Authorization Contract

**Theme:** One vocabulary, one base schema, three conforming apps

- [ ] `RMI-SYSTEMFORGE-003` Convention doc + AppVocabulary interface and vocabulary registry with scope-format and duplicate-definition validation
- [ ] `RMI-SYSTEMFORGE-004` Shared SpiceDB base schema (principal, organization, platform) and schema-composition helper
  - Depends on: `RMI-SYSTEMFORGE-003`
- [ ] `RMI-DASHFORGE-016` DashForge adoption: re-namespace SpiceDB schema to dashforge_*, conform scopes/roles, conformance test
  - Depends on: `RMI-SYSTEMFORGE-004`
- [ ] `RMI-AGENTFORGE-001` AgentForge adoption: create org-role vocabulary on the convention, conformance test
  - Depends on: `RMI-SYSTEMFORGE-004`
- [ ] `RMI-ACTIONFORGE-037` ActionForge alignment: adopt shared base organization definition and register AppVocabulary
  - Depends on: `RMI-SYSTEMFORGE-004`

## Phase 2 — IAM Console

**Theme:** AWS-IAM-style administration over registered vocabularies

- [x] `RMI-SYSTEMFORGE-005` Admin APIs: role-assignment CRUD, vocabulary introspection, scope-bounded token issuance
  - Depends on: `RMI-SYSTEMFORGE-003`
- [ ] `RMI-SYSTEMFORGEWEB-001` IAM pages: members and role assignment, roles-permissions matrix, API keys and tokens with scope picker
  - Depends on: `RMI-SYSTEMFORGE-005`

## Phase 3 — Shell Composition

**Theme:** One menu, one login, one session; Forge UIs plug in

- [ ] `RMI-SYSTEMFORGEWEB-003` Reference composed host app: shell plus two Forge UI surfaces under one login, menu, and session
  - Depends on: `RMI-SYSTEMFORGEWEB-002`
  - Depends on: `RMI-SYSTEMFORGEWEB-001`
  - Depends on: `RMI-SYSTEMFORGEWEB-023`

The registration contract, `RMI-SYSTEMFORGEWEB-002`, is tracked in
`INIT-SYSTEMFORGEWEB-001` (Phase 4, App Contract and Hosting) as the
`AppModule` and `Shell` contracts in `@plexusone/host`. The reference host
composes Forge UIs as `AppModule`s with `createHost({ apps })`.
