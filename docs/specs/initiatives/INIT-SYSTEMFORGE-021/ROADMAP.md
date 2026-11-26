# ROADMAP — Less Work in Every App

**Initiative:** `INIT-SYSTEMFORGE-021`
**Repositories:** `github.com/plexusone/systemforge`, `github.com/plexusone/systemforge-web`

Adopting email sign-in showed what every app rebuilt by hand: a hard-coded
provider list, and a guard against an address shown as a name. Put both in the
shared layer, so each app's work is a version bump and configuration. Commits
implementing an item carry `Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — One Implementation of Methods and Names

**Theme:** An app builds its buttons from the deployment and never shows an address as a name

- [x] `RMI-SYSTEMFORGE-288` `identity/displayname`: the one safe display name (`Show`, `Safe`, `Or`, the neutral default), used by the relying-party stores, `oauthclient`, the SCIM store and SystemAuth's directories; a profile whose name is an address is asked for a name
- [x] `RMI-SYSTEMFORGE-289` SystemAuth publishes its sign-in methods in discovery (`sf_sign_in_methods_supported`), the relying-party client reads them, and the BFF serves `GET /bff/auth/methods` (`BFFConfig.SignInMethods` overrides)
- [ ] `RMI-SYSTEMFORGE-290` `@plexusone/auth`: `useSignInMethods` and the BFF client's `getSignInMethods`; `@plexusone/pages`' `LoginPage` builds its buttons from them when `oauthProviders` is not given (systemforge-web)
  - Depends on: `RMI-SYSTEMFORGE-289`
- [ ] `RMI-SYSTEMFORGE-291` `@plexusone/auth`: `safeName` and `displayName`, so a web app never shows an address as a name, and the components that show names use them (systemforge-web)
- [ ] `RMI-SYSTEMFORGE-292` Release v0.39.0 and the matching web release: notes, changelog, guides
  - Depends on: `RMI-SYSTEMFORGE-288`, `RMI-SYSTEMFORGE-289`, `RMI-SYSTEMFORGE-290`, `RMI-SYSTEMFORGE-291`
