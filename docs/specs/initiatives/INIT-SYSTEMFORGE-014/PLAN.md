# PLAN — Application Authentication

**Initiative:** `INIT-SYSTEMFORGE-014`

## Approach

Build the package from the parts applications already write, keep
`identity/relyingparty` unchanged, and prove it end to end against an embedded
SystemAuth before release. Applications adopt it in their own releases after
v0.26.0. Nothing in this release forces them to.

## Phases

1. **The package.**
   - Configuration and validation, then the DPoP key, then `New` with the
     client, the BFF and memberships.
   - Then request authentication, then calling SystemAuth for the person and
     the optional features.

   Each step has its unit tests.
2. **Store, proof and docs.**
   - The Postgres principal store.
   - An end-to-end test with an example application.
   - The guide and the changes to existing pages.
   - Release notes.

## Steps

1. **`Config`, `Labels`, `Validate`, `ConfigFromEnv`, `RedirectURL`.** The
   messages and label format are fixed first, because hosts depend on them.
2. **`ParseDPoPKey`, `ReadDPoPKeyFile`, `DPoPKeyCommand`.** A fixed test key
   with a known thumbprint.
3. **`New`.**
   - The client from metadata or discovery.
   - The BFF.
   - The membership filter.
   - The store and key rules, with their warnings.
4. **Request authentication.**
   - The `requestprincipal` chain.
   - The cookie-write check.
   - `Middleware`, `Authenticate` and `Challenge`.
5. **`SessionToken` and `Transport`.** Then API keys, unbound tokens,
   accepted clients, the replay cache option and resource metadata.
6. **`pgstore.PrincipalStore`** with the conformance suite.
7. **`examples/appauth`:** a small application on an embedded SystemAuth,
   with the end-to-end test, run in the integration workflow.
8. **Documentation and the v0.26.0 release notes and changelog.**

## Risks

| Risk | Mitigation |
| --- | --- |
| The package fits one application's shape and forces others to fork | The hooks are taken from three applications with different stores, role vocabularies and error types. The success criteria require all three to adopt without forking |
| Hosts parse configuration error text to relabel it | The label format is part of the API, documented and tested |
| An always-on cookie-write check breaks an application that posts forms with the session cookie | The check matches what applications already do. The release notes call it out, and the guide shows a JSON body |
| Moving an existing principals table breaks foreign keys | The copy keeps every `id`. The guide's migration repoints keys before dropping the old table, and the example application tests it |

## Release

v0.26.0 adds a package and a store. It changes no existing API, so it is a
minor release. Its notes list the package's defaults, and the options that
loosen them, for reviewers of adopting applications.
