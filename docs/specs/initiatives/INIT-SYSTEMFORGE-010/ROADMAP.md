# ROADMAP — JWT Bearer Authorization Grant — Service Principals with Keypair Credentials

**Initiative:** `INIT-SYSTEMFORGE-010`
**Repository:** `github.com/plexusone/systemforge`

Implements the RFC 7523 JWT-bearer authorization grant on Fosite's handler,
with service principals and keypair credentials. Commits implementing an
item carry `Refs: RMI-SYSTEMFORGE-<NNN>`.

## Phase 1 — Storage and Composition

**Theme:** SystemAuth verifies signed assertions and issues scoped tokens

- [ ] `RMI-SYSTEMFORGE-118` Key-storage adapter implementing `rfc7523.RFC7523KeyStorage`: key lookup by `kid` with ownership, self-issuance, status, and expiry checks; JWK conversion; scope intersection; JTI delegation to the client-assertion store
- [ ] `RMI-SYSTEMFORGE-119` Register the JWT-bearer grant behind configuration (enabled, maximum assertion lifetime, client authentication, token lifetime) and advertise it in discovery when enabled
  - Depends on: `RMI-SYSTEMFORGE-118`
- [ ] `RMI-SYSTEMFORGE-120` Record key usage on successful exchanges and issue tokens with the service principal as subject and no refresh token
  - Depends on: `RMI-SYSTEMFORGE-119`
- [ ] `RMI-SYSTEMFORGE-121` End-to-end tests with RSA and ECDSA keys covering issuance, introspection, replay, expiry, overlong lifetime, missing `jti`, wrong audience, and revoked keys
  - Depends on: `RMI-SYSTEMFORGE-120`

## Phase 2 — Client, Documentation, Release

**Theme:** Workloads can adopt it end to end

- [ ] `RMI-SYSTEMFORGE-122` Reference client helper in `identity/oauthclient` that signs an assertion and exchanges it for a token
  - Depends on: `RMI-SYSTEMFORGE-119`
- [ ] `RMI-SYSTEMFORGE-123` Rewrite the service principals page with an end-to-end walkthrough, add release notes, tag after CI passes, and record the release
  - Depends on: `RMI-SYSTEMFORGE-121`
  - Depends on: `RMI-SYSTEMFORGE-122`
