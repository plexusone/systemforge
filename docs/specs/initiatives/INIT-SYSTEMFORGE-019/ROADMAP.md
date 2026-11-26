# ROADMAP — Names Supplied, Not Derived

**Initiative:** `INIT-SYSTEMFORGE-019`
**Repository:** `github.com/plexusone/systemforge`

Stop making a person's display name and personal organization from their email
address, and ask them instead
([ADR-024](../../../design/adrs/ADR-024-names-are-supplied-not-derived.md)).
Commits implementing an item carry `Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Names Asked, Never Derived

**Theme:** Every account's name is one its person gave

- [x] `RMI-SYSTEMFORGE-279` The display name, the personal organization's name and its slug are never made from the email address; the handle or a generated slug is used
- [x] `RMI-SYSTEMFORGE-280` The sign-up name step: a login with no name is parked, proven and bound to the browser, and asked for its name and an optional workspace name at `/signup/name` before any account is created
  - Depends on: `RMI-SYSTEMFORGE-279`
- [x] `RMI-SYSTEMFORGE-281` `SocialLoginConfig.SignInMethods` and `Server.SignInMethods`, so hosts build their sign-in buttons from the deployment
- [x] `RMI-SYSTEMFORGE-282` The directory's optional interfaces stay visible through the sign-up wrappers, so the sign-in methods page lists linked providers for deployments with a gate or an age check
- [ ] `RMI-SYSTEMFORGE-283` Release v0.38.0: notes, changelog, guides
  - Depends on: `RMI-SYSTEMFORGE-280`, `RMI-SYSTEMFORGE-281`, `RMI-SYSTEMFORGE-282`
