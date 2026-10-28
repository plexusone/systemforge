# PLAN — Service Accounts with Key-Pair Credentials

**Initiative:** `INIT-SYSTEMFORGE-010`

## Entry Gate

- PRD decisions recorded: the `service_account` membership role, and
  operator commands first.
- INIT-SYSTEMFORGE-009 released, since the grant reuses its client-assertion
  JTI store. Done.

## Build Order

### Phase 1 — Accounts and the Grant

1. Build the service-account service: accounts in an organization, keys and
   roles, with access changes.
2. Build the key-storage adapter with its refusal rules and scope
   intersection.
3. Register the Fosite factory behind configuration, require DPoP for the
   grant, and advertise the grant in discovery.
4. Issue tokens with the account as subject, the `orgs` and
   `principal_type` claims, and no refresh token. Record last use.

Exit: an embedded SystemAuth issues a DPoP-bound token for a correctly signed
assertion and refuses every PRD failure case.

### Phase 2 — Using It

1. Add the commands.
2. Add the client package.
3. Add service accounts to the relying party, `appauth` and the Postgres
   store.
4. Write the end-to-end test from command to application.
5. Update the service principals page and ADR-016, and write the release
   notes with `INIT-SYSTEMFORGE-014`'s.

Exit: PRD success criteria hold.

## Release

v0.26.0 carries this initiative and `INIT-SYSTEMFORGE-014`. Both add APIs
and change none, so the release is minor. The grant is off by default, so
deployments that do nothing see no change. `BearerConfig.ServicePrincipals`
is off by default.

## Risks and Mitigations

| Risk | Mitigation |
| --- | --- |
| Accepting a key for the wrong subject | The adapter enforces key ownership and self-issuance; direct tests |
| Enabling the grant by accident | Disabled by default; discovery advertises it only when enabled |
| Two initiatives in one release delay both | Phase 1 of each is independent; either can ship in v0.26.0 alone if the other slips, with its release notes trimmed |

## Follow-On

- **Trusted third-party issuers** (workload identity federation, such as
  GitHub Actions OIDC).
- **An HTTP API and console pages** for organization owners to manage their
  accounts.
- **IP restrictions** from `ServicePrincipal.allowed_ips` at the token
  endpoint.
