# ROADMAP — Service Accounts with Key-Pair Credentials

**Initiative:** `INIT-SYSTEMFORGE-010`
**Repository:** `github.com/plexusone/systemforge`

Service accounts that belong to an organization, hold application roles,
authenticate with a private key through the RFC 7523 JWT-bearer grant, and
call applications with short-lived DPoP-bound tokens. Commits implementing an
item carry `Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Accounts and the Grant

**Theme:** SystemAuth issues DPoP-bound tokens to service accounts in an organization

- [x] `RMI-SYSTEMFORGE-196` `identity/serviceaccount`: accounts in an organization with a `service_account` membership, key-pair keys (generated or supplied), application roles, and disable, enable, delete and key revocation recorded as access changes
- [x] `RMI-SYSTEMFORGE-118` Key-storage adapter implementing `rfc7523.RFC7523KeyStorage`: key lookup by `kid` with ownership, self-issuance, status, organization and expiry checks; JWK conversion; scope intersection; JTI delegation to the client-assertion store
  - Depends on: `RMI-SYSTEMFORGE-196`
- [x] `RMI-SYSTEMFORGE-119` Register the JWT-bearer grant behind configuration (enabled, maximum assertion lifetime, token lifetime), require a DPoP proof for it, and advertise it in discovery when enabled
  - Depends on: `RMI-SYSTEMFORGE-118`
- [x] `RMI-SYSTEMFORGE-120` Issue tokens with the service account as subject, the `orgs` and `principal_type` claims and no refresh token, and record key and account last use
  - Depends on: `RMI-SYSTEMFORGE-119`
- [x] `RMI-SYSTEMFORGE-121` End-to-end tests with P-256 and RSA keys covering issuance, introspection, DPoP binding, replay, expiry, overlong lifetime, missing `jti`, wrong audience, missing proof, revoked keys and disabled accounts
  - Depends on: `RMI-SYSTEMFORGE-120`

## Phase 2 — Using It

**Theme:** An operator sets up an account in three commands and a workload calls an application with it

- [x] `RMI-SYSTEMFORGE-197` `serviceaccountcmd`, the `service-account` commands a host mounts and `cmd/systemauth` registers: create, list, show, disable, enable and delete; `key add|list|revoke` with an owner-only private key file; `role grant|remove`
  - Depends on: `RMI-SYSTEMFORGE-196`
- [x] `RMI-SYSTEMFORGE-122` `identity/serviceclient`: signs assertions, requests DPoP-bound tokens, renews before expiry, and adds proofs to API requests with the nonce retry
  - Depends on: `RMI-SYSTEMFORGE-119`
- [x] `RMI-SYSTEMFORGE-198` Applications accept service accounts: `BearerConfig.ServicePrincipals` creates the local principal on first use, `VerifiedIdentity.Service`, `appauth.Options.ServiceAccounts`, and service identities in `pgstore.PrincipalStore`
  - Depends on: `RMI-SYSTEMFORGE-120`
  - Depends on: `RMI-SYSTEMFORGE-192`
  - Depends on: `RMI-SYSTEMFORGE-190`
- [x] `RMI-SYSTEMFORGE-199` End-to-end test from command to application: create an account, grant a role, add a key, call an `appauth` API with `serviceclient`, then remove the role and see its memberships lose the organization
  - Depends on: `RMI-SYSTEMFORGE-197`
  - Depends on: `RMI-SYSTEMFORGE-122`
  - Depends on: `RMI-SYSTEMFORGE-198`
- [x] `RMI-SYSTEMFORGE-123` Rewrite the service principals page with the walkthrough, update ADR-016 decisions 2 and 4, and add the service accounts section to the v0.26.0 release notes
  - Depends on: `RMI-SYSTEMFORGE-199`
