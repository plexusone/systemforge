# ROADMAP — Application Authentication

**Initiative:** `INIT-SYSTEMFORGE-014`
**Repository:** `github.com/plexusone/systemforge`

One package that assembles the relying party for an application, with the
same safe defaults everywhere, and a shared Postgres principal store. Commits
implementing an item carry `Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — The Package

**Theme:** An application authenticates people and programs in a few lines

- [x] `RMI-SYSTEMFORGE-187` `identity/appauth` configuration: `Config`, `Labels`, `Validate`, `ConfigFromEnv` and `RedirectURL`, with the label format hosts relabel
- [x] `RMI-SYSTEMFORGE-188` The DPoP key: `ParseDPoPKey`, `ReadDPoPKeyFile` and `DPoPKeyCommand`, required by default, with an ephemeral-key option that warns
  - Depends on: `RMI-SYSTEMFORGE-187`
- [x] `RMI-SYSTEMFORGE-189` `New`: the client from metadata or discovery, the BFF, the membership filter by application and role, and the store rules
  - Depends on: `RMI-SYSTEMFORGE-188`
- [x] `RMI-SYSTEMFORGE-190` Request authentication: the `requestprincipal` chain with extra authenticators, the cookie-write origin check, `Middleware`, `Authenticate` and `Challenge`
  - Depends on: `RMI-SYSTEMFORGE-189`
- [x] `RMI-SYSTEMFORGE-191` Calling SystemAuth for the person (`SessionToken`, `Transport`), and the options: API keys, unbound tokens, accepted clients, the replay cache and RFC 9728 resource metadata
  - Depends on: `RMI-SYSTEMFORGE-190`

## Phase 2 — Store, Proof and Docs

**Theme:** The package is proven end to end and documented as the usual way

- [x] `RMI-SYSTEMFORGE-192` `pgstore.PrincipalStore` on systemforge's `sf_rp_principals` table: `SetActive` and `Delete`, unique-violation mapping without driver types, the conformance suite, and the migration for moving an existing principals table
- [x] `RMI-SYSTEMFORGE-193` `examples/appauth` and an end-to-end test against an embedded SystemAuth: sign-in, a restart that keeps the session, bearer refused, another client's token, and a managed principal created through `Transport`
  - Depends on: `RMI-SYSTEMFORGE-191`
  - Depends on: `RMI-SYSTEMFORGE-192`
- [x] `RMI-SYSTEMFORGE-194` Documentation: the "Authenticating an application" guide, the relying-party setup example with a DPoP key, and the `session/bff` and `session/jwt` pages pointing to the package
  - Depends on: `RMI-SYSTEMFORGE-193`
- [x] `RMI-SYSTEMFORGE-195` v0.26.0 release notes and changelog
  - Depends on: `RMI-SYSTEMFORGE-194`
